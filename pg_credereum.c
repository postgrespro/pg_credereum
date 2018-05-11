#include "postgres.h"
#include "fmgr.h"
#include "funcapi.h"
#include "access/htup_details.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/indexing.h"
#include "catalog/pg_extension.h"
#include "catalog/pg_type.h"
#include "commands/extension.h"
#include "commands/trigger.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "storage/ipc.h"
#include "storage/proc.h"
#include "utils/builtins.h"
#include "utils/datum.h"
#include "utils/fmgroids.h"
#include "utils/fmgrprotos.h"
#include "utils/guc.h"
#include "utils/json.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "utils/varbit.h"

#include "openssl/rsa.h"
#include "openssl/pem.h"

#include "pg_credereum.h"
#include "ethereum.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(credereum_acc_trigger);
PG_FUNCTION_INFO_V1(credereum_get_raw_changeset);
PG_FUNCTION_INFO_V1(credereum_get_relation_id);
PG_FUNCTION_INFO_V1(credereum_sign_transaction);
PG_FUNCTION_INFO_V1(credereum_sha256);

static bool				accumulatorInitilized = false;
static bool				accumulatorFinished = false;
static bool				accumulatorIsSigned = false;
static StringInfoData	accumulatorBuffer;
static volatile sig_atomic_t shutdown_requested = false;

/* GUCs */
static int				blockPeriod;
static int				blockRetryPeriod;
static char			   *databaseName;
static char			   *schemaName;
char				   *ethRpcEndPoint;
static char			   *ethSourceAddr;
static char			   *ethContractAddr;

static RSA *rsa_make_public_key(text *key);
static bool rsa_verify_signature(bytea *msg, text *key, bytea *sign);
static char *make_json_from_row(HeapTuple tuple, TupleDesc tupleDesc);
static char *generate_qualified_relation_name(Oid relid);
static void logging_callback(XactEvent event, void *arg);
static void handle_sigterm(SIGNAL_ARGS);
static int64 millisecs_diff(TimestampTz tz1, TimestampTz tz2);
static void register_block_collector(void);
static void save_hash(bytea *hash);

/*
 * Initialize RSA public key from text.
 */
static RSA *
rsa_make_public_key(text *key)
{
	BIO	   *keybio;
	RSA	   *rsa = NULL;

	keybio = BIO_new_mem_buf(VARDATA_ANY(key), VARSIZE_ANY_EXHDR(key));

	if (!keybio)
		elog(ERROR, "Error allocating BIO");

	rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa, NULL, NULL);
	BIO_free(keybio);

	if (!rsa)
		elog(ERROR, "Error reading public key");

	return rsa;
}

/*
 * Check authenticity of signature "sign" for contents "msg" by public key
 * "key".
 */
static bool
rsa_verify_signature(bytea *msg, text *key, bytea *sign)
{
	RSA		   *pubKeyRSA;
	EVP_PKEY   *pubKey;
	EVP_MD_CTX *m_RSAVerifyCtx;
	int			authStatus;
	bool		result;

	pubKey = EVP_PKEY_new();
	pubKeyRSA = rsa_make_public_key(key);
	EVP_PKEY_assign_RSA(pubKey, pubKeyRSA);
	m_RSAVerifyCtx = EVP_MD_CTX_create();

	if (EVP_DigestVerifyInit(m_RSAVerifyCtx, NULL, EVP_sha256(), NULL, pubKey) <= 0)
	{
		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
		elog(ERROR, "Digest verification init error");
	}
	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, VARDATA_ANY(msg), VARSIZE_ANY_EXHDR(msg)) <= 0)
	{
		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
		elog(ERROR, "Digest verification update error");
	}

	authStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx,
									   (unsigned char *) VARDATA_ANY(sign),
									   VARSIZE_ANY_EXHDR(sign));
	if (authStatus == 1)
	{
		result = true;
	}
	else if (authStatus == 0)
	{
		result = false;
	}
	else
	{
		EVP_MD_CTX_destroy(m_RSAVerifyCtx);
		elog(ERROR, "Digest verification authentic check error");
	}
	EVP_MD_CTX_destroy(m_RSAVerifyCtx);

	return result;
}

/*
 * Convering given row into JSON packed into cstring.
 */
static char *
make_json_from_row(HeapTuple tuple, TupleDesc tupleDesc)
{
	FmgrInfo				callFlinfo;
	FunctionCallInfoData	callFcinfo;
	Datum					result;
	FuncExpr			   *funcExpr;
	Var					   *var;

	InitFunctionCallInfoData(callFcinfo, NULL, 1, InvalidOid, NULL, NULL);
	callFcinfo.arg[0] = heap_copy_tuple_as_datum(tuple, tupleDesc);
	callFcinfo.argnull[0] = false;

	var = makeNode(Var);
	var->vartype = tupleDesc->tdtypeid;
	funcExpr = makeNode(FuncExpr);
	funcExpr->args = lappend(NIL, var);
	callFlinfo.fn_expr = (Node *) funcExpr;
	callFcinfo.flinfo = &callFlinfo;

	result = to_json(&callFcinfo);

	return text_to_cstring(DatumGetTextP(result));
}

Datum
credereum_acc_trigger(PG_FUNCTION_ARGS)
{
	TriggerData	   *trigdata = (TriggerData *) fcinfo->context;
	TupleDesc		tupleDesc;
	char		   *relname;
	MemoryContext	oldctx;

	/* Make sure it's called as a trigger at all */
	if (!CALLED_AS_TRIGGER(fcinfo))
		elog(ERROR, "credereum_acc_trigger: not called by trigger manager");
	if (!TRIGGER_FIRED_BY_INSERT(trigdata->tg_event) &&
		!TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event) &&
		!TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
		elog(ERROR, "credereum_acc_trigger: must be called from insert, update or delete");
	if (accumulatorFinished)
		elog(ERROR, "credereum changest is already constructed");

	oldctx = MemoryContextSwitchTo(TopTransactionContext);
	if (!accumulatorInitilized)
	{
		initStringInfo(&accumulatorBuffer);
		appendStringInfo(&accumulatorBuffer, "[");
		accumulatorInitilized = true;
	}
	else
	{
		appendStringInfo(&accumulatorBuffer, ", ");
	}
	MemoryContextSwitchTo(oldctx);

	/* Log data change */
	tupleDesc = RelationGetDescr(trigdata->tg_relation);
	relname = generate_qualified_relation_name(RelationGetRelid(trigdata->tg_relation));
	if (TRIGGER_FIRED_BY_INSERT(trigdata->tg_event) ||
		TRIGGER_FIRED_BY_DELETE(trigdata->tg_event))
	{
		char *row = make_json_from_row(trigdata->tg_trigtuple, tupleDesc);

		oldctx = MemoryContextSwitchTo(TopTransactionContext);
		appendStringInfo(&accumulatorBuffer, "{\"action\": \"");
		if (TRIGGER_FIRED_BY_INSERT(trigdata->tg_event))
			appendStringInfo(&accumulatorBuffer, "insert");
		else
			appendStringInfo(&accumulatorBuffer, "delete");
		appendStringInfo(&accumulatorBuffer, "\", \"table\": ");
		escape_json(&accumulatorBuffer, relname);
		appendStringInfo(&accumulatorBuffer,
						 ", \"row\": %s}",
						 row);
		MemoryContextSwitchTo(oldctx);
	}
	else if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
	{
		char *oldrow = make_json_from_row(trigdata->tg_trigtuple, tupleDesc);
		char *newrow = make_json_from_row(trigdata->tg_newtuple, tupleDesc);

		oldctx = MemoryContextSwitchTo(TopTransactionContext);
		appendStringInfo(&accumulatorBuffer, "{\"action\": \"update\", \"table\": ");
		escape_json(&accumulatorBuffer, relname);
		appendStringInfo(&accumulatorBuffer,
						 ", \"oldrow\": %s, \"newrow\": %s}",
						 oldrow, newrow);
		MemoryContextSwitchTo(oldctx);
	}

	/* Return tuple to the executor */
	if (TRIGGER_FIRED_BY_UPDATE(trigdata->tg_event))
		return PointerGetDatum(trigdata->tg_newtuple);
	else
		return PointerGetDatum(trigdata->tg_trigtuple);
}

Datum
credereum_get_raw_changeset(PG_FUNCTION_ARGS)
{
	MemoryContext	oldctx;
	text		   *result;

	if (!accumulatorInitilized)
		PG_RETURN_NULL();

	oldctx = MemoryContextSwitchTo(TopTransactionContext);
	appendStringInfoChar(&accumulatorBuffer, ']');
	MemoryContextSwitchTo(oldctx);
	accumulatorFinished = true;

	result = cstring_to_text(accumulatorBuffer.data);

	PG_RETURN_TEXT_P(result);
}

Datum
credereum_get_relation_id(PG_FUNCTION_ARGS)
{
	Oid				relid = PG_GETARG_OID(0);
	HeapTuple		tp;
	Form_pg_class	reltup;
	char		   *relname;
	char		   *nspname;
	char		   *str;
	VarBit		   *result;
	int				len;
	int				slen;

	tp = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tp))
		elog(ERROR, "cache lookup failed for relation %u", relid);
	reltup = (Form_pg_class) GETSTRUCT(tp);
	relname = NameStr(reltup->relname);

	nspname = get_namespace_name(reltup->relnamespace);
	if (!nspname)
		elog(ERROR, "cache lookup failed for namespace %u",
			 reltup->relnamespace);

	str = quote_qualified_identifier(nspname, relname);
	slen = strlen(str);

	len = VARBITTOTALLEN(slen * BITS_PER_BYTE);
	result = (VarBit *) palloc0(len);
	SET_VARSIZE(result, len);
	VARBITLEN(result) = slen * BITS_PER_BYTE;
	memcpy(VARBITS(result), str, slen);

	ReleaseSysCache(tp);

	PG_RETURN_VARBIT_P(result);
}

Datum
credereum_sign_transaction(PG_FUNCTION_ARGS)
{
	text		   *pubkey = PG_GETARG_TEXT_P(0);
	bytea		   *sign = PG_GETARG_BYTEA_P(1);
	bytea		   *prev_hash;
	bytea		   *next_hash;
	bytea		   *msg;
	int				ret;
	Oid				argtypes[5] = {INT8OID, BYTEAOID, BYTEAOID, TEXTOID, BYTEAOID};
	bool			nulls[5] = {false, false, false, false, false};
	Datum			val;
	bool			valisnull;
	Datum			values[5];
	int64			block_num;
	char		   *query;

	if (!accumulatorInitilized)
		elog(ERROR, "No credereum transaction is in progress.");
	if (!accumulatorFinished)
		elog(ERROR, "Changeset is not yet constructed.");
	if (accumulatorIsSigned)
		elog(ERROR, "Changeset is already signed.");

	SPI_connect();

	query = psprintf("SELECT max(block_num) FROM %s.credereum_block;",
					 schemaName);
	ret = SPI_exec(query, 1);
	pfree(query);
	if (ret != SPI_OK_SELECT || SPI_processed <= 0 || !SPI_tuptable)
		elog(ERROR, "Error getting last block_num.");
	block_num = DatumGetInt64(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &valisnull)) + 1;

	values[0] = Int64GetDatum(block_num);

	query = psprintf("SELECT "
						"(SELECT hash "
						 "FROM %s.credereum_merklix "
						 "WHERE key = '' AND "
						 "block_num = $1 AND "
						 "transaction_id = pg_catalog.txid_current()) AS next_hash, "
						"(SELECT hash "
						 "FROM %s.credereum_merklix "
						 "WHERE key = '' AND "
						 "block_num = $1 - 1 AND "
						 "transaction_id IS NULL) AS prev_hash;",
					schemaName, schemaName);
	ret = SPI_execute_with_args(query, 1, argtypes, values, nulls, true, 1);
	pfree(query);

	if (ret != SPI_OK_SELECT || SPI_processed <= 0 || !SPI_tuptable)
		elog(ERROR, "Error getting signature hash.");

	val = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &valisnull);
	if (valisnull)
		elog(ERROR, "Next hash is NULL");
	next_hash = DatumGetByteaP(val);
	val = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2, &valisnull);
	if (valisnull)
		elog(ERROR, "Prev hash is NULL");
	prev_hash = DatumGetByteaP(val);

	msg = (bytea *) DatumGetPointer(
		DirectFunctionCall2(byteacat,
							PointerGetDatum(next_hash),
							PointerGetDatum(prev_hash)));

	if (rsa_verify_signature(msg, pubkey, sign))
		accumulatorIsSigned = true;
	else
		elog(ERROR, "Signature is not valid.");

	values[1] = PointerGetDatum(next_hash);
	values[2] = PointerGetDatum(prev_hash);
	values[3] = PointerGetDatum(pubkey);
	values[4] = PointerGetDatum(sign);

	query = psprintf(
		"INSERT INTO %s.credereum_tx_log (block_num, transaction_id, tx_hash, root_hash, prev_root_hash, pubkey, sign) "
		"VALUES ("
		"    $1, "
		"    pg_catalog.txid_current(), "
		"    (SELECT %s.credereum_sha256($2 || $3 || ($4::bytea) || $5)), "
		"    $2, "
		"    $3, "
		"    $4, "
		"    $5);",
		schemaName, schemaName);
	SPI_execute_with_args(query, 5, argtypes, values, nulls, false, 0);
	pfree(query);

	if (ret < 0)
		elog(ERROR, "Error inserting into log.");

	SPI_finish();

	PG_RETURN_NULL();
}

Datum
credereum_sha256(PG_FUNCTION_ARGS)
{
	SHA256_CTX	ctx;
	bytea	   *source = PG_GETARG_BYTEA_PP(0);
	bytea	   *result;

	result = (bytea *) palloc(VARHDRSZ + SHA256_DIGEST_LENGTH);
	SET_VARSIZE(result, VARHDRSZ + SHA256_DIGEST_LENGTH);
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, VARDATA_ANY(source), VARSIZE_ANY_EXHDR(source));
	SHA256_Final((uint8 *) result + VARHDRSZ, &ctx);
	PG_RETURN_BYTEA_P(result);
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
	if (!process_shared_preload_libraries_in_progress)
	{
		/* Check that the GUC variables are registered */
		const char *db = GetConfigOption("pg_credereum.database", true /* missing_ok */,
						false /* restrict_superuser */);
		if (db == NULL)
			elog(ERROR, "pg_credereum is not initialized. Make sure that"
						" it is loaded via shared_preload_libraries.");
		return;
	}

	register_block_collector();

	/* Define GUC variables */
	DefineCustomIntVariable(
			"pg_credereum.block_period",
			"Sets a period of block packing in milliseconds",
			NULL, &blockPeriod, 1000, 100, INT_MAX,
			PGC_POSTMASTER, 0, NULL, NULL, NULL);
	DefineCustomIntVariable(
			"pg_credereum.block_retry_period",
			"Sets a period of block packing retry after failure in milliseconds",
			NULL, &blockRetryPeriod, 5000, 100, INT_MAX,
			PGC_POSTMASTER, 0, NULL, NULL, NULL);
	DefineCustomStringVariable(
			"pg_credereum.database",
			"Sets name of database pg_credereum is used for.",
			NULL, &databaseName, "postgres",
			PGC_POSTMASTER, 0, NULL, NULL, NULL);
	DefineCustomStringVariable(
			"pg_credereum.schema",
			"Sets name of schema pg_credereum extension is located in.",
			NULL, &schemaName, "public",
			PGC_POSTMASTER, 0, NULL, NULL, NULL);
	DefineCustomStringVariable(
			"pg_credereum.eth_end_point",
			"Ethereum node address (host[:port]).",
			NULL, &ethRpcEndPoint, NULL,
			PGC_POSTMASTER, 0, NULL, NULL, NULL);
	DefineCustomStringVariable(
			"pg_credereum.eth_source_addr",
			"Source address for Ethereum contract execution.",
			NULL, &ethSourceAddr, NULL,
			PGC_POSTMASTER, 0, NULL, NULL, NULL);
	DefineCustomStringVariable(
			"pg_credereum.eth_contract_addr",
			"Ethereum contract address.",
			NULL, &ethContractAddr, NULL,
			PGC_POSTMASTER, 0, NULL, NULL, NULL);

	RegisterXactCallback(logging_callback, NULL);
}

static void
logging_callback(XactEvent event, void *arg)
{
	switch (event)
	{
		case XACT_EVENT_PRE_COMMIT:
			if (accumulatorInitilized)
			{
				if (!accumulatorIsSigned)
					elog(ERROR, "Transaction is not signed");
			}
			accumulatorInitilized = false;
			accumulatorFinished = false;
			accumulatorIsSigned = false;
			break;
		case XACT_EVENT_ABORT:
			accumulatorInitilized = false;
			accumulatorFinished = false;
			accumulatorIsSigned = false;
			break;
		default:
			break;
	}
}

/*
 * generate_qualified_relation_name
 *		Compute the name to display for a relation specified by OID
 *
 * As above, but unconditionally schema-qualify the name.
 */
static char *
generate_qualified_relation_name(Oid relid)
{
	HeapTuple	tp;
	Form_pg_class reltup;
	char	   *relname;
	char	   *nspname;
	char	   *result;

	tp = SearchSysCache1(RELOID, ObjectIdGetDatum(relid));
	if (!HeapTupleIsValid(tp))
		elog(ERROR, "cache lookup failed for relation %u", relid);
	reltup = (Form_pg_class) GETSTRUCT(tp);
	relname = NameStr(reltup->relname);

	nspname = get_namespace_name(reltup->relnamespace);
	if (!nspname)
		elog(ERROR, "cache lookup failed for namespace %u",
			 reltup->relnamespace);

	result = quote_qualified_identifier(nspname, relname);

	ReleaseSysCache(tp);

	return result;
}

/*
 * Register background worker for collecting blocks.
 */
static void
register_block_collector(void)
{
	BackgroundWorker worker;

	/* Set up background worker parameters */
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_ConsistentState;
	worker.bgw_restart_time = 5;
	worker.bgw_notify_pid = 0;
	StrNCpy(worker.bgw_library_name, "pg_credereum", BGW_MAXLEN);
	StrNCpy(worker.bgw_function_name, CppAsString(collector_main), BGW_MAXLEN);
	snprintf(worker.bgw_name, BGW_MAXLEN, "pg_credereum block collector");
	worker.bgw_main_arg = (Datum) 0;
	RegisterBackgroundWorker(&worker);
}

static void
handle_sigterm(SIGNAL_ARGS)
{
	int save_errno = errno;
	shutdown_requested = true;
	if (MyProc)
		SetLatch(&MyProc->procLatch);
	errno = save_errno;
}

/*
 * Delta between two timestamps in milliseconds.
 */
static int64
millisecs_diff(TimestampTz tz1, TimestampTz tz2)
{
	long	secs;
	int		microsecs;

	TimestampDifference(tz1, tz2, &secs, &microsecs);

	return secs * 1000 + microsecs / 1000;

}

/*
 * Main routine of the block collector.
 */
void
collector_main(Datum main_arg)
{
	TimestampTz		blockTs;
	char		   *schemaQuery;
	char		   *blockQuery;
	char		   *extensionSchema;
	int				period = blockPeriod;

	/*
	 * Establish signal handlers.
	 *
	 * We want CHECK_FOR_INTERRUPTS() to kill off this worker process just as
	 * it would a normal user backend.  To make that happen, we establish a
	 * signal handler that is a stripped-down version of die().  We don't have
	 * any equivalent of the backend's command-read loop, where interrupts can
	 * be processed immediately, so make sure ImmediateInterruptOK is turned
	 * off.
	 */
	pqsignal(SIGTERM, handle_sigterm);
	BackgroundWorkerUnblockSignals();

	/* Connect to our database */
	BackgroundWorkerInitializeConnection(databaseName, NULL);

	CurrentResourceOwner = ResourceOwnerCreate(NULL, "pg_credereum block collector");

	/*
	 * When the Ethereum connection is not set up, this worker still creates
	 * blocks periodically, but doesn't send them to Ethereum. To help spot a
	 * misconfiguration, show a warning if the connection is set up partially.
	 */
	if (ethRpcEndPoint || ethSourceAddr || ethContractAddr)
	{
		if (!ethRpcEndPoint)
			elog(WARNING, "pg_credereum.eth_endpoint is not set. The block hashes "
				 "will not be saved to Ethereum.");
		if (!ethSourceAddr)
			elog(WARNING, "pg_credereum.eth_source_addr is not set. The block hashes "
				 "will not be saved to Ethereum.");
		if (!ethContractAddr)
			elog(WARNING, "pg_credereum.eth_contract_addr is not set. The block hashes "
				 "will not be saved to Ethereum.");
	}


	/* Start counting time for block collection */
	blockTs = GetCurrentTimestamp();

	blockQuery = psprintf("SELECT %s.credereum_pack_block();", schemaName);
	schemaQuery = "SELECT n.nspname "
					 "FROM pg_extension e "
					 "JOIN pg_namespace n ON e.extnamespace = n.oid "
				 "WHERE e.extname = 'pg_credereum';";

	while (1)
	{
		TimestampTz		currentTs;
		int64			blockDiff;
		int				rc;
		MemoryContext	loopContext = CurrentMemoryContext,
						tmpContext;

		/* Wait calculate time to next sample for history or profile */
		currentTs = GetCurrentTimestamp();

		blockDiff = millisecs_diff(blockTs, currentTs);

		if (blockDiff > period)
		{
			/* Collect block */
			int					ret;
			Datum				hashDatum;
			bytea			   *hash = NULL;
			bool				hashisnull = true;

			period = blockRetryPeriod;
			SetCurrentStatementStartTimestamp();
			StartTransactionCommand();
			SPI_connect();
			PushActiveSnapshot(GetTransactionSnapshot());
			pgstat_report_activity(STATE_RUNNING, schemaQuery);

			ret = SPI_execute(schemaQuery, false, 1);
			if (ret != SPI_OK_SELECT || !SPI_tuptable)
				elog(ERROR, "pg_credereum block collector: error getting pg_credereum schema.");

			if (SPI_processed <= 0)
			{
				elog(LOG, "pg_credereum block collector: no pg_credereum extension is found.");
				goto nextloop;
			}

			extensionSchema = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
			if (!extensionSchema || strcmp(extensionSchema, schemaName))
			{
				elog(LOG, "pg_credereum block collector: pg_credereum schema doesn't match.");
				goto nextloop;
			}

			pgstat_report_activity(STATE_RUNNING, blockQuery);
			ret = SPI_execute(blockQuery, false, 1);
			if (ret != SPI_OK_SELECT || SPI_processed < 1)
			{
				elog(LOG, "pg_credereum block collector: block collection is failed.");
				goto nextloop;
			}

			hashDatum = SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &hashisnull);
			if (!hashisnull)
			{
				tmpContext = MemoryContextSwitchTo(loopContext);
				hash = DatumGetByteaPP(datumCopy(hashDatum, false, -1));
				MemoryContextSwitchTo(tmpContext);
			}

			period = blockPeriod;

nextloop:
			SPI_finish();
			PopActiveSnapshot();
			CommitTransactionCommand();
			pgstat_report_stat(false);
			pgstat_report_activity(STATE_IDLE, NULL);
			blockTs = currentTs;

			/* Save hash to ethereum */
			if (!hashisnull && ethRpcEndPoint && ethSourceAddr && ethContractAddr)
			{
				StartTransactionCommand();
				SPI_connect();
				PushActiveSnapshot(GetTransactionSnapshot());

				save_hash(hash);

				SPI_finish();
				PopActiveSnapshot();
				CommitTransactionCommand();
			}

			if (!hashisnull)
				pfree(hash);

			continue;
		}

		/* Shutdown if requested */
		if (shutdown_requested)
			break;

		rc = WaitLatch(&MyProc->procLatch, WL_LATCH_SET | WL_TIMEOUT | WL_POSTMASTER_DEATH,
					   period - blockDiff, PG_WAIT_EXTENSION);

		if (rc & WL_POSTMASTER_DEATH)
			proc_exit(1);

		ResetLatch(&MyProc->procLatch);
	}

	/*
	 * We're done.  Explicitly detach the shared memory segment so that we
	 * don't get a resource leak warning at commit time.  This will fire any
	 * on_dsm_detach callbacks we've registered, as well.  Once that's done,
	 * we can go ahead and exit.
	 */
	proc_exit(0);
}

static void
save_hash(bytea *hash)
{
	char	   *hashString;

	hashString = palloc0(VARSIZE_ANY_EXHDR(hash) * 2 + 1);
	hex_encode(VARDATA_ANY(hash), VARSIZE_ANY_EXHDR(hash), hashString);

	EthCallContext c = {0};
	c.sourceAccount = readUint256(ethSourceAddr);
	c.contractAccount = readUint256(ethContractAddr);
	c.signature = "saveHash(uint256)";
	c.isConstant = false;
	ethParseMethodSignature(&c);
	c.paramValues[0] = hashString;
	ethCallMethod(&c);
	elog(LOG, "Saved block hash %s to Ethereum (transaction %s)",
		 hashString, printUint256(c.ethTxId));
}

