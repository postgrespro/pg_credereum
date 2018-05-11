/*-------------------------------------------------------------------------
 *
 * ethereum.c
 *		Routines for integration with Ethereum.
 *
 * Copyright (c) 2017-2018, Postgres Professional
 *
 * Author: Alexander Kuzmenkov <a.kuzmenkov@postgrespro.ru>
 *
 * IDENTIFICATION
 *	  contrib/pg_credereum/ethereum.c
 *
 *-------------------------------------------------------------------------
 */
#include "ethereum.h"
#include "pg_credereum.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <jansson.h>
#include <curl/curl.h>

#include "postgres.h"
#include "utils/elog.h"

#if HAVE_BYTESWAP_H
#include <byteswap.h>
#else
#define bswap_16(value) \
((((value) & 0xff) << 8) | ((value) >> 8))

#define bswap_32(value) \
(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define bswap_64(value) \
(((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
<< 32) | \
(uint64_t)bswap_32((uint32_t)((value) >> 32)))
#endif

#define BUFFER_SIZE  (256 * 1024)  /* 256 KB */

#define URL_SIZE     256

uint256
makeUint256(unsigned int a)
{
	return (uint256) { .i32 = { 0, 0, 0, 0, 0, 0, 0, bswap_32(a) } };
}

uint32_t
makeUint32(uint256 a)
{
	return bswap_32(a.i32[7]);
}

char *
printUint256(uint256 n)
{
	return psprintf("0x%.8x%.8x%.8x%.8x%.8x%.8x%.8x%.8x",
			bswap_32(n.i32[0]), bswap_32(n.i32[1]),
			bswap_32(n.i32[2]), bswap_32(n.i32[3]),
			bswap_32(n.i32[4]), bswap_32(n.i32[5]),
			bswap_32(n.i32[6]), bswap_32(n.i32[7]));
}

char *
printAddress(uint256 n)
{
	char* cut = printUint256(n) + 24;
	cut[0] = '0';
	cut[1] = 'x';
	return cut;
}

char *
debugPrintHex(void* buf, int bytes)
{
	int dwords = (bytes + 4 - 1) / 4;
	int len = dwords * 8 + 2 + (dwords / 8);
	char* result = palloc(len + 1);
	result[0] = '0';
	result[1] = 'x';
	result[len] = 0;
	int ll = 2;
	for (int i = 0; i < dwords; i++) {
		sprintf(&result[ll], "%.8x", bswap_32(((uint32_t *)buf)[i]));
		ll += 8;
		if (i % 8 == 7) {
			sprintf(&result[ll], ".");
			ll++;
		}
	}
	return result;
}

static char
toDigit(char x)
{
	ethAssert(x >= 0);
	ethAssert(x <= 0xf);
	return x > 9 ? 'a' + x - 10: '0' + x;
}

char *
printHex(void *_buf, int bytes)
{
	char *buf = (char*) _buf;
	char *s = palloc(bytes * 2 + 3);
	s[0] = '0';
	s[1] = 'x';
	s[2 + bytes * 2] = 0;
	for (int i = 0; i < bytes; i++)
	{
		s[2 + i * 2 + 1] = toDigit(buf[i] & 0x0f);
		s[2 + i * 2] = toDigit((buf[i] & 0xf0) >> 4);
	}
	return s;
}

static char
fromDigit(char x)
{
	x = tolower(x);
	ethAssert(('0' <= x && x <= '9') || ('a' <= x && x <= 'f'));
	return x > '9' ? x - 'a' + 10 : x - '0';
}

void
readHex(const char* s, char** buf, int *bufLen)
{
	if (s[0] == '0' && s[1] == 'x') {
		s += 2;
	}
	int n = strlen(s);
	ethCheck(n % 2 == 0, "cannot decode a hex string of odd length: '%s'", s);
	*bufLen = n / 2;
	*buf = palloc(*bufLen);
	for (int i = 0; i < *bufLen; i++)
	{
		(*buf)[i] = fromDigit(s[i * 2]) << 4 | fromDigit(s[i * 2 + 1]);
	}
}

uint256
readUint256(const char *s)
{
	return readUint256n(s, strlen(s));
}

uint256
readUint256n(const char *s, int l)
{
	uint256 result = {};
	if (l >= 2 && s[0] == '0' && s[1] == 'x') {
		s += 2;
		l -= 2;
	}
	const int lSegment = 8;
	const int n = (l + lSegment - 1) / lSegment;
	char buf[lSegment + 1];
	buf[lSegment] = 0;
	for (int i = n - 1; i >= 0; i--) {
		const int segStart = MAX(0, l - (i + 1) * lSegment);
		const int segEnd = l - i * lSegment;
		const int segLength = segEnd - segStart;
		strncpy(buf, &s[segStart], segLength);
		result.i32[8 - i - 1] = bswap_32(strtoull(buf, 0, 16));
	}

	return result;
}

static EthParamType
readParamType(char *begin, char *end)
{
	int l = end - begin;
	if (strncmp(begin, "uint256", l) == 0)
		return EPT_Uint;
	else if (strncmp(begin, "string", l) == 0)
		return EPT_String;
	else if (strncmp(begin, "address", l) == 0)
		return EPT_Address;
	else if (strncmp(begin, "raw", l) == 0)
		return EPT_Raw;

	ethCheck(false, "unknown argument type: %.*s", (int)(end - begin), begin);
}

/* Parses a comma-separated list of type names, terminated by ')' or '\0' */
static void
parseParams(char **c, EthParamType *paramTypes, int *nParams)
{
	while (**c && **c != ')')
	{
		char *begin = *c;
		ethCheck(*nParams < ETH_MAX_PARAMS, "too many params (%d)", *nParams);
		for(; **c && **c != ')' && **c !=','; (*c)++)
			;
		paramTypes[(*nParams)++] = readParamType(begin, *c);
		if (**c == ',')
			(*c)++;
	}
}

static char *
escapeChar(char x)
{
	return x ? psprintf("%c", x) : "\\0";
}

#define signExpect(x) ethCheck(*c == (x), \
	"failed to parse function signature '%s': expected '%s', got '%s' at character %d", \
	context->signature, escapeChar(x), escapeChar(*c), (int)(c - context->signature))

/*
 * Parses signature into parameter and return types, and
 * computes the hash for method selector
 */
void
ethParseMethodSignature(EthCallContext *context)
{
	char *c;
	for (c = context->signature; *c && *c != '('; c++)
		;
	signExpect('(');
	c++;

	parseParams(&c, context->paramTypes, &context->nParams);

	signExpect(')');
	c++;

	context->sigHash = sha3n(context->signature, c - context->signature).i32[0];

	/* parse the optional return type list */
	if (*c == 0)
		return;

	signExpect('=');
	c++;
	signExpect('>');
	c++;

	parseParams(&c, context->returnTypes, &context->nReturn);

	signExpect(0);
}

struct write_result
{
	char *data;
	int pos;
};

static size_t
write_response(void *ptr, size_t size, size_t nmemb, void *stream)
{
	struct write_result *result = (struct write_result *)stream;

	ethCheck(result->pos + size * nmemb < BUFFER_SIZE - 1,
		  "cannot read the response: the buffer is too small" );

	memcpy(result->data + result->pos, ptr, size * nmemb);
	result->pos += size * nmemb;

	return size * nmemb;
}

#define GET_CURL_ERROR (strlen(curlError) ? curlError : curl_easy_strerror(status))
#define	rpcCheck(cond, rest...)	\
	if (!(cond)) { \
		errstart(ERROR, __FILE__, __LINE__, PG_FUNCNAME_MACRO, TEXTDOMAIN); \
		errmsg("eth: jsonpc: " rest); \
		goto error; \
	}

static json_t *
jsonrpc_run(char *request)
{
	//printf("req: %s\n", request);

	json_t *result = NULL;
	struct curl_slist *headers = NULL;
	long code;
	char* data = 0;

	char *curlError = palloc(CURL_ERROR_SIZE);
	CURLcode status;

	CURL *curl = curl_easy_init();
	rpcCheck(curl != 0, "failed to initialize curl");

	data = palloc(BUFFER_SIZE);
	struct write_result write_result = { .data = data, .pos = 0 };

	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlError);
	curl_easy_setopt(curl, CURLOPT_URL, ethRpcEndPoint);

	headers = curl_slist_append(headers, "User-Agent: postgrethereum");
	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, "Accept: application/json");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_result);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long) strlen(request));
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);

	status = curl_easy_perform(curl);
	rpcCheck(status == 0, "failed to send the request: %s", GET_CURL_ERROR);

	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
	rpcCheck(code == 200, "error: server responded with code %ld", code);

	/* zero-terminate the result */
	data[write_result.pos] = '\0';

	//printf("resp: %s\n", data);

	json_error_t error;
	json_t *root = json_loads(data, 0, &error);
	rpcCheck(root != 0, "failed parse the response '%s': '%s'", data,
			   error.text);
	rpcCheck(json_is_object(root), "response must be a JSON object: '%s'",
		   data);
	json_t *returnedError = json_object_get(root, "error");
	rpcCheck(returnedError == 0, "the call completed with error: '%s'",
			   json_dumps(returnedError, JSON_COMPACT));

	result = json_object_get(root, "result");
	rpcCheck(result != 0, "no result in the response: '%s'",
		   json_dumps(root, JSON_COMPACT));
	return result;

error:
	if(curlError)
		pfree(curlError);
	if(data)
		pfree(data);
	if(curl)
		curl_easy_cleanup(curl);
	if(headers)
		curl_slist_free_all(headers);

	errfinish(0);
	pg_unreachable();
}

json_t *
ethSendTransaction(uint256 from, uint256 to, const char *payload)
{
	char *reqTemplate = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\""
			",\"params\":[{\"from\":\"%s\", \"to\":\"%s\", \"data\":\"%s\","
			"\"gas\":\"0x30000\"}],\"id\":1}"
			;
	char *req = psprintf(reqTemplate, printAddress(from), printAddress(to),
						 payload);
	return jsonrpc_run(req);
}

json_t *
ethCall(uint256 from, uint256 to, const char *payload)
{
	char *reqTemplate = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\""
			",\"params\":[{\"from\":\"%s\", \"to\":\"%s\", \"data\":\"%s\","
			"\"gas\":\"0x30000\"}"
			", \"latest\"],\"id\":1}"
			;
	char *req = psprintf(reqTemplate, printAddress(from), printAddress(to),
						 payload);
	return jsonrpc_run(req);
}

void
ethCallMethod(EthCallContext *c)
{
	int dataOffset[ETH_MAX_PARAMS];
	int headerOffset[ETH_MAX_PARAMS];

	int headerLength = 0;
	for (int i = 0; i < c->nParams; i++)
	{
		headerOffset[i] = headerLength;
		headerLength += 32;
	}

	int totalLength = headerLength;
	for (int i = 0; i < c->nParams; i++)
	{
		dataOffset[i] = totalLength;
		switch (c->paramTypes[i]) {
			case EPT_Uint:
			case EPT_Address:
				/* header only */
				break;

			case EPT_String:
			{
				/* 32b length + string characters aligned to 32 bytes */
				totalLength += 32 + 32 * ((strlen(c->paramValues[i]) + 31) / 32);
				break;
			}

			default:
				ethAssert(false);
		}
	}

	int payloadSize = 4 + totalLength;
	char* payload = palloc(payloadSize);
	*(uint32_t*)payload = c->sigHash;

	char* params = payload + 4;

	for (int i = 0; i < c->nParams; i++)
	{
		switch (c->paramTypes[i]) {
			case EPT_Address:
			case EPT_Uint:
				*(uint256 *) &params[headerOffset[i]] = readUint256(c->paramValues[i]);
				break;

			case EPT_String:
			{
				int l = strlen(c->paramValues[i]);
				int ll = 32 * ((l + 31) / 32);
				*(uint256 *) &params[headerOffset[i]] = makeUint256(dataOffset[i]);
				*(uint256 *) &params[dataOffset[i]] = makeUint256(l);
				memcpy(params + dataOffset[i] + 32, c->paramValues[i], l);
				memset(params + dataOffset[i] + 32 + l, 0, ll - l);
				break;
			}

			default:
				ethAssert(false);
		}
	}

	char *encodedPayload = printHex(payload, payloadSize);

	if (c->isConstant)
	{
		json_t *result = ethCall(c->sourceAccount, c->contractAccount,
								 encodedPayload);
		ethAssert(json_is_string(result));
		
		/* 
		 * eth_call returns the data returned by the smart contract method.
		 * Parse it into individual return values according to the method
		 * signature.
		 */
		
		char *buf;
		int bufLength;
		readHex(json_string_value(result), &buf, &bufLength);

		if (bufLength == 0)
			return;
			
		headerLength = c->nReturn * 32;
		ethAssert(headerLength <= bufLength);
		for (int i = 0; i < c->nReturn; i++)
		{
			int valueOffset = 0;
			int valueLength = 0;
			switch (c->returnTypes[i]) {
				case EPT_Address:
				case EPT_Uint:
					c->returnValues[i] = printUint256(((uint256 *) buf)[i]);
					break;

				case EPT_String:
					valueOffset = makeUint32(((uint256 *) buf)[i]);
					ethAssert(valueOffset < bufLength);
					valueLength = makeUint32(*(uint256 *) &buf[valueOffset]);
					ethAssert(valueOffset + 32 + valueLength <= bufLength);
					c->returnValues[i] = palloc(valueLength + 1);
					memcpy(c->returnValues[i], &buf[valueOffset + 32], valueLength);
					c->returnValues[i][valueLength] = 0;
					break;

				case EPT_Raw:
					c->returnValues[i] = (char*) json_string_value(result);
					break;

				default:
					ethAssert(false);
			}
		}
	}
	else
	{
		/* eth_sendTransaction returns the ethereum transaction id */
		json_t *result = ethSendTransaction(c->sourceAccount, c->contractAccount,
											encodedPayload);
		ethAssert(json_is_string(result));
		c->ethTxId = readUint256(json_string_value(result));
	}
}

json_t *
getTransactionReceipt(uint256 transactionId)
{
	char *reqTemplate = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionReceipt\""
			",\"params\":[\"%s\"],\"id\":1}"
			;
	char *req = psprintf(reqTemplate, printUint256(transactionId));
	return jsonrpc_run(req);
}

json_t *
getTransaction(uint256 transactionId)
{
	char *reqTemplate = "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getTransactionByHash\""
			",\"params\":[\"%s\"],\"id\":1}"
			;
	char *req = psprintf(reqTemplate, printUint256(transactionId));
	return jsonrpc_run(req);
}

int
getCurrentBlockNumber()
{
	json_t *result = jsonrpc_run("{\"jsonrpc\":\"2.0\", \"method\":\"eth_blockNumber\""
								 ", \"params\":[], \"id\":1}");
	ethAssert(json_is_string(result));
	return strtoull(json_string_value(result), 0, 16);
}

int
getTxBlock(uint256 tid)
{
	json_t *tx = getTransaction(tid);
	if (json_is_null(tx))
	{
		/* a nonexistent transaction */
		return -2;
	}
	ethAssert(json_is_object(tx));

	json_t* receipt = getTransactionReceipt(tid);
	if (json_is_null(receipt))
	{
		/* the transaction is still pending */
		return 0;
	}
	ethAssert(json_is_object(receipt));

	json_t *statusJson = json_object_get(receipt, "status");
	if (statusJson)
	{
		/* use status field introduced in Byzantium */
		ethAssert(json_is_string(statusJson));
		int status = strtoul(json_string_value(statusJson), 0, 16);
		if (status == 0)
		{
			/* execution failed */
			return -1;
		}
	}
	else
	{
		/* use a recommended heuristic: used gas == max gas => failed */
		json_t *txGasJson = json_object_get(tx, "gas");
		ethAssert(txGasJson != 0);
		ethAssert(json_is_string(txGasJson));
		int txGas = strtoul(json_string_value(txGasJson), 0, 16);
		ethAssert(txGas >= 0);

		json_t *txGasUsedJson = json_object_get(receipt, "gasUsed");
		ethAssert(txGasUsedJson != 0);
		ethAssert(json_is_string(txGasUsedJson));
		int txGasUsed = strtoul(json_string_value(txGasUsedJson), 0, 16);
		ethAssert(txGasUsed >= 0);

		if (txGasUsed == txGas)
		{
			/* execution failed */
			return -1;
		}
	}

	json_t* n = json_object_get(receipt, "blockNumber");
	ethAssert(n != NULL);
	ethAssert(json_is_string(n));

	return strtoul(json_string_value(n), 0, 16);
}

//////////////////////////////////////////////////////////////////////////////

/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */

#define decshake(bits) \
	int shake##bits(uint8_t*, size_t, const uint8_t*, size_t);

#define decsha3(bits) \
	int sha3_##bits(uint8_t*, size_t, const uint8_t*, size_t);

#define deckeccak(bits) \
	int keccak##bits(uint8_t*, size_t, const uint8_t*, size_t);

	decshake(128)
	decshake(256)
	decsha3(224)
	decsha3(256)
	decsha3(384)
	decsha3(512)
	deckeccak(224)
	deckeccak(256)
	deckeccak(384)
deckeccak(512)

	/******** The Keccak-f[1600] permutation ********/

	/*** Constants. ***/
	static const uint8_t rho[24] = \
{ 1,  3,   6, 10, 15, 21,
	28, 36, 45, 55,  2, 14,
	27, 41, 56,  8, 25, 43,
	62, 18, 39, 61, 20, 44};
static const uint8_t pi[24] = \
{10,  7, 11, 17, 18, 3,
	5, 16,  8, 21, 24, 4,
	15, 23, 19, 13, 12, 2,
	20, 14, 22,  9, 6,  1};
static const uint64_t RC[24] = \
{1ULL, 0x8082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
	0x808bULL, 0x80000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x8aULL, 0x88ULL, 0x80008009ULL, 0x8000000aULL,
	0x8000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x80000001ULL, 0x8000000080008008ULL};

/*** Helper macros to unroll the permutation. ***/
#define rol(x, s) (((x) << s) | ((x) >> (64 - s)))
#define REPEAT6(e) e e e e e e
#define REPEAT24(e) REPEAT6(e e e e)
#define REPEAT5(e) e e e e e
#define FOR5(v, s, e) \
	v = 0;            \
REPEAT5(e; v += s;)

/*** Keccak-f[1600] ***/
static inline void
keccakf(void* state) {
	uint64_t* a = (uint64_t*)state;
	uint64_t b[5] = {0};
	uint64_t t = 0;
	uint8_t x, y;

	for (int i = 0; i < 24; i++) {
		// Theta
		FOR5(x, 1,
				b[x] = 0;
				FOR5(y, 5,
					b[x] ^= a[x + y]; ))
			FOR5(x, 1,
					FOR5(y, 5,
						a[y + x] ^= b[(x + 4) % 5] ^ rol(b[(x + 1) % 5], 1); ))
			// Rho and pi
			t = a[1];
		x = 0;
		REPEAT24(b[0] = a[pi[x]];
				a[pi[x]] = rol(t, rho[x]);
				t = b[0];
				x++; )
			// Chi
			FOR5(y,
					5,
					FOR5(x, 1,
						b[x] = a[y + x];)
					FOR5(x, 1,
						a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]); ))
			// Iota
			a[0] ^= RC[i];
	}
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/

#undef _
#define _(S) do { S } while (0)
#define FOR(i, ST, L, S) \
	_(for (size_t i = 0; i < L; i += ST) { S; })
#define mkapply_ds(NAME, S)                                          \
	static inline void NAME(uint8_t* dst,                              \
			const uint8_t* src,                        \
			size_t len) {                              \
		FOR(i, 1, len, S);                                               \
	}
#define mkapply_sd(NAME, S)                                          \
	static inline void NAME(const uint8_t* src,                        \
			uint8_t* dst,                              \
			size_t len) {                              \
		FOR(i, 1, len, S);                                               \
	}

	mkapply_ds(xorin, dst[i] ^= src[i])  // xorin
mkapply_sd(setout, dst[i] = src[i])  // setout

#define P keccakf
#define Plen 200

	// Fold P*F over the full blocks of an input.
#define foldP(I, L, F) \
		while (L >= rate) {  \
			F(a, I, rate);     \
			P(a);              \
			I += rate;         \
			L -= rate;         \
		}

	/** The sponge-based hash construction. **/
	static inline int hash(uint8_t* out, size_t outlen,
			const uint8_t* in, size_t inlen,
			size_t rate, uint8_t delim) {
		if ((out == NULL) || ((in == NULL) && inlen != 0) || (rate >= Plen)) {
			return -1;
		}
		uint8_t a[Plen] = {0};
		// Absorb input.
		foldP(in, inlen, xorin);
		// Xor in the DS and pad frame.
		a[inlen] ^= delim;
		a[rate - 1] ^= 0x80;
		// Xor in the last block.
		xorin(a, in, inlen);
		// Apply P
		P(a);
		// Squeeze output.
		foldP(out, outlen, setout);
		setout(a, out, outlen);
		memset(a, 0, 200);
		return 0;
	}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
#define defshake(bits)                                            \
	int shake##bits(uint8_t* out, size_t outlen,                    \
			const uint8_t* in, size_t inlen) {              \
		return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x1f);  \
	}
#define defsha3(bits)                                             \
	int sha3_##bits(uint8_t* out, size_t outlen,                    \
			const uint8_t* in, size_t inlen) {              \
		if (outlen > (bits/8)) {                                      \
			return -1;                                                  \
		}                                                             \
		return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x06);  \
	}
#define defkeccak(bits)                                             \
	int keccak##bits(uint8_t* out, size_t outlen,                    \
			const uint8_t* in, size_t inlen) {              \
		if (outlen > (bits/8)) {                                      \
			return -1;                                                  \
		}                                                             \
		return hash(out, outlen, in, inlen, 200 - (bits / 4), 0x01);  \
	}

/*** FIPS202 SHAKE VOFs ***/
	defshake(128)
defshake(256)

	/*** FIPS202 SHA3 FOFs ***/
	defsha3(224)
	defsha3(256)
	defsha3(384)
defsha3(512)

	/*** KECCAK FOFs ***/
	defkeccak(224)
	defkeccak(256)
	defkeccak(384)
defkeccak(512)

uint256 sha3(uint256 v)
{
	uint256 result = {{0}};
	keccak256((unsigned char*)&result, 32, (unsigned char*)&v, sizeof(v));
	return result;
}

uint256 sha3_2(uint256 a, uint256 b)
{
	uint256 source[2] = {a, b};
	uint256 result = {{0}};
	keccak256((unsigned char*)&result, 32, (unsigned char*)&source, sizeof(a)*2);
	return result;
}

uint256 sha3n(const char* s, int n)
{
	uint256 result = {{0}};
	keccak256((unsigned char*)&result, 32, (unsigned char*) s, n);
	return result;
}

uint256 sha3s(const char* s)
{
	return sha3n(s, strlen(s));
}
