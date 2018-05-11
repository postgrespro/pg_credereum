pg\_credereum
=============

Overview
--------

pg\_credereum is a PostgreSQL extension that provides a cryptographically
verifiable audit capability for a PostgreSQL database, bringing some properties
of blockchain to the relational DBMS. pg\_credereum is not a production-ready
solution yet, it's a prototype for the upcoming Credereum platform.

In a classical client-server DBMS, a client relies on the server to guarantee
the integrity and authenticity of data. A client has to believe that the data
provided by server is correct without any proof. Even if the server supports
audit, the audit data could be forged by the server administrator or
compromised by an intruder.

The blockchain systems allow their state to be traced to individial actions of
their clients, that are authenticated by their respective digital signatures.
Credereum aims to bring this capability of blockchain to a client-server
relational DBMS. In Credereum, every modification to the contents of the
database is digitally signed by the client that performs the modification.
Based on these signatures, the server can build a proof that attributes the
current database contents to the previous actions of the clients. The clients
check this proof to verify that the contents of the database were not tampered
with.

A well-known "double spending" problem the blockchain implementations have to
solve also applies to Credereum. A malicious database administrator may
maintain multiple forks of the database, and answer the queries of different
users based on these different forks. In order to prevent that, Credereum
creates a cryptographic digest of the entire database contents. This digest is
periodically recorded to a trusted storage which clients can read. This storage
must be immutable, that is, once the data is recorded in the storage, it must
not be possible to change this data retroactively. This way, a client can be
sure that once a database digest reaches the trusted storage, it can't be
removed or changed anymore. This allows a client to detect any retroactive
modification of the data.

In principle, various systems may serve as a trusted storage. For example, a
public blockchain like Ethereum or Bitcoin with a smart contract to store the
hashes can serve as such a storage. Another way to implement trusted storage is
to use a third-party server that is trusted not to allow retroactive changes.
Yet another example is a cluster of servers, where each server signs the hash
it accepts, and hash is assumed to be accepted once it's signed by a majority
of the servers. pg\_credereum uses an Ethereum smart contract as a trusted
storage.


Implementation
-----------

In Credereum, every modification of the database contents is signed by the
client that made it. Namely, the client signs a digest of the original and
modified data. This digest must have certain properties:
1. It is compact, compared to the size of the entire database.
2. It allows to detect forgery (i.e., it is hard to change the database
   contents in such a way that the digest does not change).
3. The client can verify that the digest corresponds to the correct values of
   the modified rows.
4. The digest does not divulge the values of the unmodified rows.

A well-known data structure that meets these requirements is a Merkle prefix
tree ("merklix tree"). pg\_credereum builds a single merklix tree for all the
tables it manages. The tree is built over the set of key-value pairs, each pair
representing a single row. The values are given by json-encoded rows, and the
keys are given by a string consisting of the schema qualified table name,
followed by a string encoding the value of the primary key as a 64-bit binary
number. Hashes in merklix tree are calculated as follows: for a leaf node, the
hash value is calculated as sha256 hash of the `value` field. For a non-leaf
node, the has value is calculated as sha256 of concatenation of child1 key,
child1 hash, ... etc for all the children.

The hash of the root node of merklix tree summarizes the contents of the entire
database. We also refer to this hash as "root database hash". A "Merkle proof"
is used to prove that a particular leaf node of the tree contains a particular
value, without revealing the whole tree. Merkle proof is a subtree of merklix
tree that contains the root node, the leaf nodes to be proven, and the path
from root to these leaves. The Merkle proof also contain nodes directly
referenced by the path from the root to the leaves to be proven. The whole
contents of these nodes are not needed, so they are represented just by their
hash values.

### Signing a transaction

If tables are represented as a merklix tree, a modification of these tables can
be encoded as a pair of Merkle proofs. Both proofs encode only the rows that
are being changed, with the "original" proof encoding the original row values,
and the "updated" proof -- the updated values. The client checks the
authenticity of the original state of the database as described below. It then
verifies that the modification it made transform the original proof into the
updated proof. Finally, the client signs the concatenation of the hashes of
these proofs, thus authorizing the transaction.

### Transaction blocks

The simple scheme described above, with every transaction depending on the
previous one, effectively serializes database access, therefore limiting the
transaction throughput. As an optimization, pg\_credereum uses "blocks of
transactions", that is, sequential sets of transaction. These blocks are
created periodically by a background worker. The contents of the database at
the end of the block are represented with a Merkle proof for all the rows that
were changed within the block. The subsequent transactions use this proof as
the digest of the original database state. This way, multiple transactions can
run concurrently. A limitation of this approach is that a particular row can
be modified only once inside a particular block. Transaction that violate this
rule are rolled back. 

The end of a block is a suitable point to publish a database digest to a
trusted storage. pg\_credereum can be configured to send the hash of a block to
an Ethereum smart contract.

### Verifying the database contents

Given the particular row values, a client should be able to check that these
values are authentic, that is, they are a result of a series of modifications
authorized by other clients. We start the verification with a database state
that we consider to be valid. It may be just an empty database, or, in a more
practical case, a block published to a trusted storage. We then request the
history of transactions that modified the given rows since the initial state.
Having checked that each of these transaction was authorized by some other
client, and the composition of these transactions transforms the initial state
into the final state, we conclude that the final state is authentic.

This procedure is used, in particular, to verify the authenticity of a given
block, starting from some previous block that is known to be authentic.


Installation
------------

pg\_credereum is a PostgreSQL extension that requires PostgreSQL 10. Before you
build and install the extension, make sure that:
 * PostgreSQL major version is 10.
 * The development package of PostgreSQL is installed or you have built
   PostgreSQL from source.
 * go-ethereum, curl and jasson are installed.
 * The pg\_config command can be found in your PATH, or the PG\_CONFIG variable
   is pointing to it.

A typical installation procedure may look like this:

```shell
git clone https://github.com/postgrespro/pg_credereum.git
cd pg_credereum
make
sudo make install
```

After the installation, add pg\_credereum to `shared_preload_libraries` to let
it register the block collector background worker. Also consider setting the
GUC variables listed in 'usage' section.

When you finish editing the PostgreSQL configuration, you may finally create
the pg\_credereum extension in the database:

```shell
psql DB -c "CREATE EXTENSION pg_credereum;"
```

Usage
-----

### Setup

For now, pg\_credereum usage is limited to a single database of a PostgreSQL
instance. This limitation might be addressed in the future versions. The name
of the database managed by pg\_credereum is specified by the GUC variable
`pg_credereum.database`.

pg\_credereum includes a "block collector" background worker, which
periodically creates transaction blocks.  The period is defined
`pg_credereum.block_period` GUC variable. Block collector has to know which
schema pg\_credereum is defined in. So, this schema must be specified in the
`pg_credereum.schema` GUC variable.

Block collector can also store block hashes into a trusted storage. When
`pg_credereum.eth_end_point`, `pg_credereum.eth_source_addr` and
`pg_credereum.eth_contract_addr` GUCs are defined, the block collector tries to
store every block hash to a smart contract at the address
`pg_credereum.eth_contract_addr` using Ethereum RPC at
`pg_credereum.eth_end_point`, sending the transactions from the Ethereum
address specified by `pg_credereum.eth_source_addr`. Note that the
corresponding Ethereum account must be unlocked on the Ethereum node. When the
block collector fails to store the block hash, it skips the block and tries to
store the hash of the next block. The hashes are stored using the
`saveHash(uint256)` method of the smart contract.

The the list of all pg\_credereum GUCs is present below.

 GUC                              | Type      | Default    | Description
--------------------------------- | --------- | ---------- | --------------------------------------------------------------
`pg_credereum.block_period`       | `integer` | 1000       | Period for block packing in milliseconds
`pg_credereum.block_retry_period` | `integer` | 5000       | Period for block packing retry after failure in milliseconds
`pg_credereum.database`           | `string`  | `postgres` | Name of database pg\_credereum is working with.
`pg_credereum.schema`             | `string`  | `public`   | Schema where pg\_credereum extension is installed.
`pg_credereum.eth_end_point`      | `string`  | `NULL`     | Ethereum trusted storage RPC endpoint in format `host[:port]`.
`pg_credereum.eth_source_addr`    | `string`  | `NULL`     | Source address to spend ether from.
`pg_credereum.eth_contract_addr ` | `string`  | `NULL`     | Smart contract to store top database hashes.

By default, pg\_credereum does not track changes to any tables.  To track a
table, add a `credereum_acc_trigger()` trigger after each insert, update and
delete. You have to revoke truncate right on that table from non-superusers,
because pg\_credereum can't handle truncates. Also note that the primary key of
this table must be single column named `id` of type `bigint`.

The following SQL snippet demonstrates how set up such a table:
```sql
CREATE TABLE t (id serial PRIMARY KEY, value int NOT NULL);
CREATE TRIGGER t_after AFTER INSERT OR UPDATE OR DELETE ON t
FOR EACH ROW EXECUTE PROCEDURE credereum_acc_trigger();
REVOKE TRUNCATE ON t FROM public;
```

### API

This section described how to use the functions and tables provided by
pg\_credereum to sign the transactions and verify the contents of the database.

The procedure to sign the transaction is as follows:
1. Client begins new transaction.
2. Client performs DML operations on the tables.
3. Client gets changeset made by it at the step #2 in the form of Merkle proof
   using `credereum_get_changeset()` function.  Client checks that given
   changeset is really corresponging to the changes it made at #2.
4. Client signs the transaction (a transition from one root database hash to
   another) using `credereum_sign_transaction(pubkey text, sign bytea)` function.  
5. Client commits the transaction.

The procedure to acquire and validate the history of given database rows is as
follows: 
1. User acquires history of given database rows with appropriate Merkle proofs
   using `credereum_merkle_proof(keys varbit[])` function and fetches
   information about transactional history and blocks from `credereum_tx_log`
   and `credereum_block`. When user got required information, he checks its
   consistency.
2. User fetches hashes store in the trusted storage, and checks that they match
   block hashes got from the database.

#### `credereum_get_changeset()`

Returns changes made by the current transaction. The changes are represented a
set of rows, each of these rows corresponding to a merklix node. The following
columns are returned:

 Column name | Type       | Description
------------ | ---------- | ---------------------------------------------------------------------------------------------------------------
`key`        | `varbit`   | Key of merklix node
`children`   | `varbit[]` | Array of children keys (for non-leaf nodes)
`leaf`       | `bool`     | Is this a leaf node?
`hash`       | `bytea`    | Hash sum validating this node and descendants
`value`      | `json`     | Value stored in leaf node
`next`       | `bool`     | `false` for the original values of the rows modified by the current transaction, and `true` for the new values.

Logically, the result of `credereum_get_changeset()` function consists of the
two Merkle proofs mentioned above:

1. Merkle proof of the original values of the rows modified by the current transaction (`next = false`);
2. Merkle proof of the current values of the rows modified by the current transaction (`next = true`).

Each Merkle proof is a subtree of merklix tree. The `value` field of leaf nodes
is a json representation of the corresponding rows. Some non-leaf nodes can
have `children` set to `NULL`, and some leaf nodes can have `value` field set
to `NULL`. This means that the entire subtree or the leaf respectively were not
modified by this transaction.

Note that the same row can't be modified twice during the same block. On an
attempt to do this, unique constraint violation error will be generated. If
such errors happen too frequently, consider decreasing the value of the
`pg_credereum.block_period` GUC variable.

#### `credereum_merkle_proof(keys varbit[])`  

Returns the history of a particular set of rows.  `keys` are the merlix tree
keys of the nodes, as described in the [Implementation](#implementation)
section. The return value is a set of rows, with each row representing a
merklix node. The columns are as follows:

Column name      | Type       | Description
---------------- | ---------- | -----------
`block_num`      | `bigint`   | The number of the block this node belongs to
`transaction_id` | `bigint`   |  Transaction ID this node belongs to (NULL it's a block node)
`key`            | `varbit`   | Key of merklix node
`children`       | `varbit[]` | Array of children keys (for non-leaf nodes)
`leaf`           | `bool`     | Is this a leaf node?
`hash`           | `bytea`    | Hash sum validating this node and descendants
`value`          | `json`     | Value stored in leaf node

Logically, the result of `credereum_merkle_proof(keys varbit[])` function is a
forest of Merkle proofs. Since a transaction or even a block typically modify
only a relatively small subset of the database, this forest contain common
branches.

Each tree in the forest is identified by pair `block_number`, `transaction_id`.
Each block and each transaction have its own tree root. However, `children`
array of tree node may contain links to nodes of previous block tree. General
rule is following: if key is referenced by `children` array and there is no
such key with same values of `block_number`, `transaction_id`, then child
should be found in most recent `block_number` (`transaction_id` is NULL). The
rules of tree hashing is the same as described in 'signing transaction'
section.

The tree of particular block must contain merged changes of every transaction
in the same `block_number`.

#### `credereum_tx_log` table
This table contains the list of transactions. It has the following columns:

 Column name     | Type     | Description
---------------- | -------- | ------------------------------------------------------------
`block_num`      | `bigint` | The number of the block that contains this transaction
`transaction_id` | `bigint` | Transaction ID this node belongs to (NULL it's a block node)
`tx_hash`        | `bytea`  | Hash sum of the transaction
`root_hash`      | `bytea`  | Root database hash after this transaction
`prev_root_hash` | `bytea`  | Root database hash before this transaction
`pubkey`         | `text`   | Public key of user signed this transaction
`sign`           | `bytea`  | Digital signature of transaction

Hash of transaction (`credereum_tx_log.tx_hash`) is calculated as sha256 hash
of concatenation of `root_hash`, `prev_root_hash`, `pubkey`, and `sign`.

#### `credereum_block` table
This table contains the list of blocks. It has the following columns:

 Column name | Type        | Description
------------ | ----------- | -------------------------------------------------
`block_numr` | `bigint`    | The serial number of this block
`hash`       | `bytea`     | Hash sum of this block
`prev_hash`  | `bytea`     | Hash of previous block
`root_hash`  | `bytea`     | Root database hash after completion of this block

Hash of block (`credereum_block.hash`) is calculated as concetenation as sha256
hash of concatenation of `prev_hash`, hashes of transactions in this block
ordered by `transaction_id`, `root_hash`.

If hashes of the blocks are also stored to trusted storage in Ethereum, then
hashes stored in `credereum_block.hash` needs to be compared with hashes
stored in the Ethereum.  Note, that some hashes might be missed in the Ethereum,
because block collector might skip some blocks on error.  However, the
sequence of the blocks can't be altered.

Sample application
------------------

The `sample` folder of this repository contains an example of how to use
pg\_credereum from a Python 3 application, as well as how to interface it with
Ethereum. Required Python packages can be installed with `pip3 install -r requirements.txt`.
The bash scrip `run` demonsrates overall usage of pg\_credereum. If you
run this script directly, note that it will kill your `geth` process. It also requires
`geth`, `solc` and PostgreSQL binaries to be found in PATH. The script starts a
PostgreSQL instance with a table managed by pg\_credereum. It also starts a
private Ethereum network with a smart contract to store the block hashes. After
updating the table with the `sample.py` script, it runs the `history_proof.py`
script that checks that the state of the database is consistent with what is
stored in the Ethereum smart contract.

Besides the scripts mentioned above, there are some other files:
 * `hts_eth/HashStorage.sol` -- a reference implementation of the Ethereum hash
   storage contract. 
 * `credereum.py` -- Python helper functions for dealing with pg\_credereum,
   which are used by `sample.py` and `history_proof.py`
