/* contrib/pg_credereum/pg_credereum--0.1.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_credereum" to load this file. \quit

/*-------------------------------------------------------------------------
 *
 * pg_credereum--0.1.sql
 *		SQL-functions and declarations providing functionality of
 *		pg_credereum extension.
 *
 * Copyright (c) 2017-2018, Postgres Professional
 *
 * Author: Alexander Korotkov <a.korotkov@postgrespro.ru>
 *
 * IDENTIFICATION
 *	  contrib/pg_credereum/pg_credereum--0.1.sql
 *
 *-------------------------------------------------------------------------
 */

CREATE FUNCTION credereum_acc_trigger()
RETURNS trigger
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT SECURITY DEFINER;

CREATE FUNCTION credereum_get_raw_changeset()
RETURNS json
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT;

CREATE FUNCTION credereum_get_relation_id(regclass)
RETURNS varbit
AS 'MODULE_PATHNAME'
LANGUAGE C STABLE STRICT;

CREATE FUNCTION credereum_sign_transaction(pubkey text, sign bytea)
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C STRICT SECURITY DEFINER;

CREATE FUNCTION credereum_sha256(bytea)
RETURNS bytea
AS 'MODULE_PATHNAME'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE TABLE credereum_merklix
(
	key				varbit NOT NULL,
	block_num		bigint NOT NULL,
	transaction_id	bigint,
	children		varbit[],
	leaf			bool NOT NULL,
	hash			bytea,
	value			json,
	CHECK (leaf OR value IS NULL) -- Non-leafs doesn't have values
);

-- Initial state: empty merklix
INSERT INTO credereum_merklix (key, block_num, hash, leaf, transaction_id)
VALUES ('', 0, credereum_sha256(''), false, NULL);

CREATE UNIQUE INDEX credereum_merklix_key_block_num_leaf_with_tx_unique_idx
ON credereum_merklix (key, block_num)
WHERE leaf AND transaction_id IS NOT NULL;

CREATE UNIQUE INDEX credereum_merklix_key_block_num_leaf_without_tx_unique_idx
ON credereum_merklix (key, block_num)
WHERE leaf AND transaction_id IS NULL;

CREATE INDEX credereum_merklix_key_block_num_with_tx_idx
ON credereum_merklix (key, block_num)
WHERE transaction_id IS NOT NULL;

CREATE INDEX credereum_merklix_key_block_num_without_tx_idx
ON credereum_merklix (key, block_num)
WHERE transaction_id IS NULL;

CREATE TABLE credereum_tx_log
(
	block_num		bigint NOT NULL,
	transaction_id	bigint NOT NULL,
	tx_hash			bytea NOT NULL,
	root_hash		bytea NOT NULL,
	prev_root_hash	bytea NOT NULL,
	pubkey			text NOT NULL,
	sign			bytea NOT NULL,
	PRIMARY KEY (block_num, transaction_id)
);

CREATE TABLE credereum_block
(
	block_num		bigint NOT NULL PRIMARY KEY,
	hash			bytea NOT NULL,
	prev_hash		bytea NOT NULL,
	root_hash		bytea NOT NULL
);

INSERT INTO credereum_block (block_num, hash, prev_hash, root_hash)
VALUES (0, credereum_sha256(credereum_sha256('') || credereum_sha256('')), credereum_sha256(''), credereum_sha256(''));

REVOKE ALL ON credereum_merklix FROM public;
REVOKE ALL ON credereum_tx_log FROM public;
REVOKE ALL ON credereum_block FROM public;
GRANT SELECT ON credereum_tx_log TO public;
GRANT SELECT ON credereum_block TO public;

CREATE OR REPLACE FUNCTION credereum_longest_prefix(k1 varbit, k2 varbit) RETURNS varbit AS $$
DECLARE
	len			int;
	i			int;
	prefix		varbit;
BEGIN
	len := least(length(k1), length(k2));
	i := 1;
	prefix := ''::varbit;
	WHILE substring(k1, i, 1) = substring(k2, i, 1) AND i <= len LOOP
		prefix := prefix || substring(k1, i, 1);
		i := i + 1;
	END LOOP;
	RETURN prefix;
END;
$$ LANGUAGE plpgsql STRICT;

CREATE OR REPLACE FUNCTION credereum_merklix_insert(_key varbit, _value json, _block_num bigint, _transaction_id bigint) RETURNS void AS $$
DECLARE
	curkey				varbit;
	curchildren			varbit[];
	newchildren			varbit[];
	block_num			bigint;
	cur_transaction_id	bigint;
	update_children		bool;
	prefixes			varbit[];
	child_idx			int;
	do_break			bool;
BEGIN
	curkey := '';
	LOOP
		block_num := NULL;
		IF _transaction_id IS NOT NULL THEN
			SELECT mh.children, mh.block_num INTO curchildren, block_num
			FROM @extschema@.credereum_merklix mh
			WHERE key = curkey AND
				  mh.block_num = _block_num AND
				  transaction_id = _transaction_id;
		END IF;
		IF block_num IS NULL THEN
			SELECT mh.children, mh.block_num INTO curchildren, block_num
			FROM @extschema@.credereum_merklix mh
			WHERE key = curkey AND
				  mh.block_num <= _block_num AND
				  transaction_id IS NULL
			ORDER BY block_num DESC LIMIT 1;
		END IF;

		update_children := false;

		IF curchildren IS NULL OR array_length(curchildren, 1) = 0 THEN
			curchildren := ARRAY[_key];
			update_children := true;
			do_break := true;
		ELSE
			prefixes := ARRAY[@extschema@.credereum_longest_prefix(curchildren[1], _key)];
			child_idx := 1;
			IF array_length(curchildren, 1) = 2 THEN
				prefixes[2] := @extschema@.credereum_longest_prefix(curchildren[2], _key);
				IF length(prefixes[2]) > length(prefixes[1]) THEN
					child_idx := 2;
				END IF;
			END IF;
			IF length(prefixes[child_idx]) = 0 THEN
				IF array_length(curchildren, 1) <> 1 THEN
					RAISE EXCEPTION E'Can\'t append child!';
				END IF;
				curchildren := curchildren || _key;
				child_idx := 2;
				update_children := true;
				do_break := true;
			ELSIF length(prefixes[child_idx]) = length(curchildren[child_idx]) THEN
				-- Full match
				IF curchildren[child_idx] = _key THEN
					do_break := true;
				ELSE
					do_break := false;
				END IF;
			ELSE
				-- Partial match, insert new node
				newchildren := ARRAY[LEAST(curchildren[child_idx], _key),
									 GREATEST(curchildren[child_idx], _key)];
				INSERT INTO @extschema@.credereum_merklix (key, block_num, children, leaf, transaction_id)
				VALUES (prefixes[child_idx], _block_num, newchildren, false, _transaction_id);
				curchildren[child_idx] := prefixes[child_idx];
				update_children := true;
				do_break := true;
			END IF;
		END IF;

		IF block_num IS NULL OR block_num < _block_num THEN
			INSERT INTO @extschema@.credereum_merklix (key, block_num, children, leaf, transaction_id)
			VALUES (curkey, _block_num, curchildren, false, _transaction_id);
		ELSIF update_children THEN
			IF _transaction_id IS NOT NULL THEN
				UPDATE @extschema@.credereum_merklix m
				SET children = curchildren
				WHERE m.key = curkey AND
					  m.block_num = _block_num AND
					  m.transaction_id = _transaction_id;
			ELSE
				UPDATE @extschema@.credereum_merklix m
				SET children = curchildren
				WHERE m.key = curkey AND
					  m.block_num = _block_num AND
					  m.transaction_id IS NULL;
			END IF;
		END IF;

		IF do_break THEN
			EXIT;
		ELSE
			curkey = curchildren[child_idx];
		END IF;
	END LOOP;

	INSERT INTO @extschema@.credereum_merklix (key, block_num, leaf, value, transaction_id)
	VALUES (_key, _block_num, true, _value, _transaction_id);
END;
$$ LANGUAGE plpgsql CALLED ON NULL INPUT;

CREATE OR REPLACE FUNCTION credereum_merklix_get_hash(_key varbit, _block_num bigint, _transaction_id bigint) RETURNS bytea AS $$
DECLARE
	_leaf			bool;
	_hash			bytea;
	_cur_block_num	bigint;
	_value			json;
	_children		varbit[];
	data			bytea;
BEGIN
	IF _transaction_id IS NOT NULL THEN
		SELECT leaf, hash, value, children, block_num
		INTO _leaf, _hash, _value, _children, _cur_block_num
		FROM @extschema@.credereum_merklix
		WHERE key = _key AND
			  block_num = _block_num AND
			  transaction_id = _transaction_id;
	END IF;
	IF _leaf IS NULL THEN
		SELECT leaf, hash, value, children, block_num
		INTO _leaf, _hash, _value, _children, _cur_block_num
		FROM @extschema@.credereum_merklix
		WHERE key = _key AND
			  block_num <= _block_num AND
			  transaction_id IS NULL
		ORDER BY block_num DESC LIMIT 1;
	END IF;

	-- Return precalculated hash if any
	IF _hash IS NOT NULL THEN
		RETURN _hash;
	END IF;
	IF _cur_block_num <> _block_num THEN
		RAISE EXCEPTION 'non-calculated hash in previous block_num';
	END IF;
	IF _leaf THEN
		data := _key::text::bytea || ':'::bytea || _value::text::bytea;
	ELSE
		IF _children IS NULL OR array_length(_children, 1) = 0 OR array_length(_children, 1) > 2 THEN
			RAISE EXCEPTION 'invalid number of children %', _key;
		END IF;
		data := _children[1]::text::bytea || ':'::bytea || @extschema@.credereum_merklix_get_hash(_children[1], _block_num, _transaction_id);
		IF array_length(_children, 1) = 2 THEN
			data := data || ',' || _children[2]::text::bytea || ':'::bytea || @extschema@.credereum_merklix_get_hash(_children[2], _block_num, _transaction_id);
		END IF;
	END IF;
	_hash := @extschema@.credereum_sha256(data);
	IF _transaction_id IS NOT NULL THEN
		UPDATE @extschema@.credereum_merklix SET hash = _hash
		WHERE key = _key AND
			  block_num = _block_num AND
			  transaction_id = _transaction_id;
	ELSE
		UPDATE @extschema@.credereum_merklix SET hash = _hash
		WHERE key = _key AND
			  block_num = _block_num AND
			  transaction_id IS NULL;
	END IF;
	RETURN _hash;
END;
$$ LANGUAGE plpgsql CALLED ON NULL INPUT;

CREATE OR REPLACE FUNCTION credereum_merklix_get_hash(_block_num bigint, _transaction_id bigint) RETURNS bytea AS $$
	SELECT @extschema@.credereum_merklix_get_hash(''::varbit, _block_num, _transaction_id);
$$ LANGUAGE sql CALLED ON NULL INPUT;

CREATE OR REPLACE FUNCTION credereum_apply_transaction(data json) RETURNS bigint AS $$
DECLARE
	r				record;
	element			json;
	key				varbit;
	value			json;
	action			text;
	id				bigint;
	next_block_num	bigint;
	prev_hash		bytea;
	root_hash		bytea;
	contents_hash	bytea;
	hash			bytea;
	my_txid			bigint;
BEGIN
	-- Prevent concurrent packing of block
	LOCK TABLE @extschema@.credereum_tx_log IN ROW EXCLUSIVE MODE;
	SELECT b.block_num + 1, b.root_hash INTO next_block_num, prev_hash
	FROM @extschema@.credereum_block b
	ORDER BY block_num DESC LIMIT 1;
	my_txid := txid_current();
	FOR element IN SELECT json_array_elements(data) LOOP
		action := element->>'action';
		IF action = 'insert' THEN
			value := element->'row';
			id := (value->>'id')::bigint;
		ELSIF action = 'update' THEN
			value := element->'newrow';
			id := (value->>'id')::bigint;
		ELSIF action = 'delete' THEN
			value := 'null';
			id := (element->'row'->>'id')::bigint;
		ELSE
			RAISE EXCEPTION 'invalid action %', action;
		END IF;
		key := @extschema@.credereum_get_relation_id((element->>'table')::regclass)||(id::bit(64));
		PERFORM @extschema@.credereum_merklix_insert(key, value, next_block_num, my_txid);
	END LOOP;
	root_hash := @extschema@.credereum_merklix_get_hash(next_block_num, my_txid);
	RETURN next_block_num;
END;
$$ LANGUAGE plpgsql STRICT;

CREATE OR REPLACE FUNCTION credereum_get_changeset(OUT key varbit, OUT children varbit[], OUT leaf bool, OUT hash bytea, OUT value json, OUT next bool) RETURNS SETOF record AS $$
DECLARE
	blknum			bigint;
	keys			varbit[];
	my_txid			bigint;
BEGIN
	blknum := @extschema@.credereum_apply_transaction(
									@extschema@.credereum_get_raw_changeset());
	my_txid := txid_current();
	keys := (SELECT array_agg(m.key)
			 FROM @extschema@.credereum_merklix m
			 WHERE m.leaf AND
				   m.block_num = blknum AND
				   m.transaction_id = my_txid);
	RETURN QUERY
		SELECT mp.*, false FROM @extschema@.credereum_merkle_proof(keys, blknum - 1) mp UNION ALL
		SELECT mp.*, true FROM @extschema@.credereum_merkle_proof(keys, blknum, my_txid) mp;
END;
$$ LANGUAGE plpgsql STRICT SECURITY DEFINER;

--
-- Merkle proof for given array of keys in given block_num.
--
CREATE OR REPLACE FUNCTION credereum_merkle_proof(
	keys varbit[], blknum bigint,
	OUT key varbit, OUT children varbit[], OUT leaf bool, OUT hash bytea, OUT value json)
RETURNS SETOF record AS $$
WITH RECURSIVE k AS (
	SELECT key FROM unnest(keys) key
),
t AS (
	SELECT mh.key, mh.block_num, mh.children, mh.leaf, mh.hash, mh.value
	FROM @extschema@.credereum_merklix mh
	WHERE mh.key = '' AND mh.block_num = blknum AND mh.transaction_id IS NULL
UNION ALL
	SELECT
		mh.key,
		mh.block_num,
		(CASE WHEN mh.match THEN mh.children ELSE NULL END) AS children,
		mh.leaf,
		mh.hash,
		(CASE WHEN mh.match THEN mh.value ELSE NULL END) AS value
	FROM
		t,
		LATERAL (
			SELECT *, EXISTS (SELECT * FROM k WHERE @extschema@.credereum_longest_prefix(k.key, mhh.key) = mhh.key) AS match FROM (
			(SELECT mh.* FROM @extschema@.credereum_merklix mh
			  WHERE mh.key = t.children[1] AND
					mh.transaction_id IS NULL AND
					mh.block_num <= blknum
			  ORDER BY mh.block_num DESC LIMIT 1)
			UNION ALL
			(SELECT mh.* FROM @extschema@.credereum_merklix mh
			  WHERE mh.key = t.children[2] AND
					mh.transaction_id IS NULL AND
					mh.block_num <= blknum
			  ORDER BY mh.block_num DESC LIMIT 1)) mhh
		) mh
)
SELECT key, children, leaf, hash, value FROM t;
$$ LANGUAGE sql CALLED ON NULL INPUT;

--
-- Merkle proof for given array of keys in given block_num
-- and transaction.
--
CREATE OR REPLACE FUNCTION credereum_merkle_proof(
	keys varbit[], blknum bigint, txid bigint,
	OUT key varbit, OUT children varbit[], OUT leaf bool, OUT hash bytea, OUT value json)
RETURNS SETOF record AS $$
WITH RECURSIVE k AS (
	SELECT key FROM unnest(keys) key
),
t AS (
	SELECT mh.key, mh.block_num, mh.children, mh.leaf, mh.hash, mh.value
	FROM @extschema@.credereum_merklix mh
	WHERE mh.key = '' AND mh.block_num = blknum AND mh.transaction_id = txid
UNION ALL
	SELECT
		mh.key,
		mh.block_num,
		(CASE WHEN mh.match THEN mh.children ELSE NULL END) AS children,
		mh.leaf,
		mh.hash,
		(CASE WHEN mh.match THEN mh.value ELSE NULL END) AS value
	FROM
		t,
		LATERAL (
			SELECT *, EXISTS (SELECT * FROM k WHERE @extschema@.credereum_longest_prefix(k.key, mhh.key) = mhh.key) AS match FROM (
			(SELECT * FROM
			  ((SELECT mh.* FROM @extschema@.credereum_merklix mh
			   WHERE mh.key = t.children[1] AND
					 mh.block_num = blknum AND
					 mh.transaction_id = txid)
			  UNION ALL
			  (SELECT mh.* FROM @extschema@.credereum_merklix mh
			   WHERE mh.key = t.children[1] AND
					 mh.block_num < blknum AND
					 mh.transaction_id IS NULL
			   ORDER BY mh.block_num DESC LIMIT 1)) t
			 ORDER BY t.block_num DESC LIMIT 1)
			 UNION ALL
			(SELECT * FROM
			  ((SELECT mh.* FROM @extschema@.credereum_merklix mh
			   WHERE mh.key = t.children[2] AND
					 mh.block_num = blknum AND
					 mh.transaction_id = txid)
			  UNION ALL
			  (SELECT mh.* FROM @extschema@.credereum_merklix mh
			   WHERE mh.key = t.children[2] AND
					 mh.block_num < blknum AND
					 mh.transaction_id IS NULL
			   ORDER BY mh.block_num DESC LIMIT 1)) t
			 ORDER BY t.block_num DESC LIMIT 1)) mhh
		) mh
)
SELECT key, children, leaf, hash, value FROM t;
$$ LANGUAGE sql CALLED ON NULL INPUT;

--
-- Merkle proof for the whole history of given keys.
--
CREATE OR REPLACE FUNCTION credereum_merkle_proof(keys varbit[],
	OUT block_num bigint, OUT transaction_id bigint, OUT key varbit, OUT children varbit[], OUT leaf bool, OUT hash bytea, OUT value json)
RETURNS SETOF record AS $$
WITH RECURSIVE k AS (
	SELECT key FROM unnest(keys) key
),
t AS (
	SELECT mh.block_num, mh.transaction_id, mh.key, mh.children, mh.leaf, mh.hash, mh.value
	FROM @extschema@.credereum_merklix mh
	WHERE mh.key = ''
UNION ALL
	SELECT
		mh.block_num,
		mh.transaction_id,
		mh.key,
		(CASE WHEN mh.match THEN mh.children ELSE NULL END) AS children,
		mh.leaf,
		mh.hash,
		(CASE WHEN mh.match THEN mh.value ELSE NULL END) AS value
	FROM
		(SELECT mhh.*, EXISTS (SELECT * FROM k WHERE @extschema@.credereum_longest_prefix(k.key, mhh.key) = mhh.key) AS match FROM
			(SELECT DISTINCT ON (mhhh.key, mhhh.block_num, mhhh.transaction_id) mhhh.*
			 FROM @extschema@.credereum_merklix mhhh, t
			 WHERE (mhhh.key = t.children[1] OR mhhh.key = t.children[2])
			 AND mhhh.block_num = t.block_num
			 AND mhhh.transaction_id IS NOT DISTINCT FROM t.transaction_id) mhh) mh
)
SELECT
	DISTINCT ON (block_num, transaction_id, key)
	block_num, transaction_id, key, children, leaf, hash, value
FROM t;
$$ LANGUAGE sql CALLED ON NULL INPUT SECURITY DEFINER
;

CREATE OR REPLACE FUNCTION credereum_pack_block() RETURNS bytea AS $$
DECLARE
	_root_hash		bytea;
	_prev_hash		bytea;
	block_hash		bytea;
	blknum			bigint;
BEGIN
	LOCK TABLE @extschema@.credereum_tx_log IN SHARE ROW EXCLUSIVE MODE;
	LOCK TABLE @extschema@.credereum_block IN SHARE ROW EXCLUSIVE MODE;
	SELECT block_num + 1, hash INTO blknum, _prev_hash
	FROM @extschema@.credereum_block
	ORDER BY block_num DESC LIMIT 1;
	IF (SELECT count(*) FROM @extschema@.credereum_tx_log l WHERE l.block_num = blknum) = 0 THEN
		RETURN NULL;
	END IF;
	PERFORM
		@extschema@.credereum_merklix_insert(key, value, blknum, NULL)
	FROM
		@extschema@.credereum_merklix m
	WHERE
		m.leaf AND
		m.block_num = blknum AND
		m.transaction_id IS NOT NULL;
	_root_hash := @extschema@.credereum_merklix_get_hash(blknum, NULL);
	block_hash := @extschema@.credereum_sha256(
		_prev_hash ||
		(SELECT string_agg(l.tx_hash, '' ORDER BY l.transaction_id ASC)
		 FROM @extschema@.credereum_tx_log l
		 WHERE l.block_num = blknum) ||
		_root_hash);
	INSERT INTO @extschema@.credereum_block (block_num, hash, prev_hash, root_hash)
	VALUES (
		blknum,
		block_hash,
		_prev_hash,
		_root_hash);
	RETURN block_hash;
END;
$$ LANGUAGE plpgsql STRICT;
