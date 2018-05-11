#!/usr/bin/env python3
import json
import hashlib
import sys
import binascii
from OpenSSL import crypto

class ValidationError(Exception):
	def __init__(self, value):
		self.value = value
	def __str__(self):
		return repr(self.value)

def check_tree_hash(tree, key):
	data = b''
	node = tree[key]
	node['orpham'] = False
	if node['leaf']:
		if node['value'] is None:
			return
		data = (key + ':' + node['value']).encode('utf-8')
	else:
		if node['children'] is None:
			return
		for child in node['children']:
			if data != b'':
				data = data + b','
			check_tree_hash(tree, child)
			data = data + (child + ':').encode('utf-8') + tree[child]['hash']
	actualHash = hashlib.sha256(data).digest()
	expectedHash = node['hash']
	if actualHash != expectedHash:
		raise ValidationError('hashes of key %s don\'t match: %s vs %s, %s' % (key, binascii.hexlify(actualHash), binascii.hexlify(expectedHash), binascii.hexlify(data)));

def check_for_orphams(tree):
	for key in tree:
		if tree[key]['orpham']:
			raise ValidationError('key %s is orpham' % (key,));

def check_empty_nodes(tree1, tree2):
	for key in tree1:
		node = tree1[key]
		empty = False;
		if node['leaf']:
			if node['value'] is None:
				symNode = tree2[key]
				if symNode['value'] is not None or symNode['hash'] != node['hash']:
					raise ValidationError('empty keys "%s" mismatch' % (key,));
		else:
			if node['children'] is None and key != '':
				symNode = tree2[key]
				if symNode['children'] is not None or symNode['hash'] != node['hash']:
					raise ValidationError('empty keys "%s" mismatch' % (key,));

def get_changeset(dbconn, progress = False):
	oldTree = {}
	newTree = {}
	cursor = dbconn.cursor()
	if progress:
		sys.stdout.write("Getting transaction changeset from the server:\n")
		sys.stdout.write("	Receiving merklix...")
	cursor.execute("SELECT key, children, leaf, hash, value::text AS value, next FROM credereum_get_changeset();")
	row = cursor.fetchone()
	while row:
		if row[1]:
			children = row[1][1:-1].split(',')
		else:
			children = None
		node = {
			'children'	: children,
			'leaf'		: row[2],
			'hash'		: bytes(row[3]),
			'value'		: row[4],
			'orpham'	: True
		}
		if row[5]:
			newTree[row[0]] = node;
		else:
			oldTree[row[0]] = node;
		row = cursor.fetchone()
	cursor.close()
	if progress:
		sys.stdout.write(" done\n")

	# Check both tree hashes
	if progress:
		sys.stdout.write("	Checking hashes...")
	check_tree_hash(oldTree, '')
	check_tree_hash(newTree, '')
	if progress:
		sys.stdout.write(" done\n")

	# Check trees have no orphams
	if progress:
		sys.stdout.write("	Checking for orphams...")
	check_for_orphams(oldTree)
	check_for_orphams(newTree)
	if progress:
		sys.stdout.write(" done\n")

	# Check empty nodes
	if progress:
		sys.stdout.write("	Checking empty nodes...")
	check_empty_nodes(oldTree, newTree)
	check_empty_nodes(newTree, oldTree)
	if progress:
		sys.stdout.write(" done\n")

	# Extract changeset
	if progress:
		sys.stdout.write("	Extracting changeset...")
	changeset = {'inserts': [], 'updates': [], 'deletes': [], 'hash': newTree['']['hash'] + oldTree['']['hash']}
	for key in newTree:
		node = newTree[key]
		if not node['leaf'] or node['value'] is None or node['value'] == 'null':
			continue
		if key in oldTree and oldTree[key]['value'] != 'null':
			changeset['updates'].append({'key': key, 'newValue': json.loads(node['value']), 'oldValue': json.loads(oldTree[key]['value'])})
		else:
			changeset['inserts'].append({'key': key, 'value': json.loads(node['value'])})

	for key in oldTree:
		node = oldTree[key]
		if not node['leaf'] or node['value'] is None or node['value'] == 'null':
			continue
		if not key in newTree or newTree[key]['value'] == 'null':
			changeset['deletes'].append({'key': key, 'value': json.loads(node['value'])})
	if progress:
		sys.stdout.write(" done\n")
	return changeset

def int_to_bin(value, size):
	s = ''
	for i in range(0, size):
		if value % 2 == 1:
			s = '1' + s
		else:
			s = '0' + s
		value = value // 2
	return s

def str_to_bin(s):
	l = len(s)
	res = ''
	for i in range(0, l):
		value = ord(s[i])
		res = res + int_to_bin(value, 8)
	return res

def get_key(tableName, id):
	return str_to_bin(tableName) + int_to_bin(id, 64)

def make_tree(oldTree, newTree, key):
	if (not key in newTree) and (key in oldTree):
		newTree[key] = oldTree[key]
	if key in newTree:
		node = newTree[key]
		if node['children']:
			for child in node['children']:
				make_tree(oldTree, newTree, child)

def check_no_key_proof(tree, key):
	curKey = ''
	while True:
		if curKey not in tree or tree[curKey]['children'] is None:
			if curKey == '' and curKey in tree:
				return;
			raise ValidationError('no proof for absent key %s' % (key,));
		for child in tree[curKey]['children']:
			if key.startswith(child):
				curKey = child
		break

# Get history of given set of keys with proof, and check that proof
def get_history_proof(dbconn, keys):
	# Fetch information about blocks
	blockNums = []
	blockTransactions = {}
	blocks = {}
	cursor = dbconn.cursor()
	cursor.execute(
		"SELECT block_num, hash, prev_hash, root_hash " +
		"FROM credereum_block " +
		"ORDER BY block_num")
	row = cursor.fetchone()
	prevHash = hashlib.sha256(b'').digest() # Initial hash
	while row:
		block = {
			'block_num'		: row[0],
			'hash'			: bytes(row[1]),
			'prev_hash'		: bytes(row[2]),
			'root_hash'		: bytes(row[3]),
		}
		if block['prev_hash'] != prevHash:
			raise ValidationError('block chain is broken at %s' % (str(block['block_num']),));
		prevHash = block['hash']
		blockNums.append(block['block_num'])
		blocks[block['block_num']] = block
		blockTransactions[block['block_num']] = []
		row = cursor.fetchone()

	# Fetch information about transactions
	transactions = {}
	cursor = dbconn.cursor()
	cursor.execute(
		"SELECT "
			"block_num, transaction_id, tx_hash, root_hash, "
			"prev_root_hash, pubkey, sign " +
		"FROM credereum_tx_log " +
		"ORDER BY block_num, transaction_id")
	row = cursor.fetchone()
	while row:
		if not row[0] in blockTransactions:
			# Transaction is not yet packed into block, so skip it
			row = cursor.fetchone()
			continue

		blockTransactions[row[0]].append(row[1])
		transaction = {
			'block_num'		: row[0],
			'transaction_id'	: row[1],
			'tx_hash'			: bytes(row[2]),
			'root_hash'			: bytes(row[3]),
			'prev_root_hash'	: bytes(row[4]),
			'pubkey'			: row[5],
			'sign'				: bytes(row[6]),
		}
		transactions[(row[0], row[1])] = transaction
		data = transaction['root_hash'] + transaction['prev_root_hash'] + transaction['pubkey'].encode('utf-8') + transaction['sign']
		if hashlib.sha256(data).digest() != transaction['tx_hash']:
			raise ValidationError('transaction %s of block number %s hash mismatch' % (str(row[1]), str(row[0])));
		row = cursor.fetchone()

	# Validate hashes of blocks
	prev_root_hash = hashlib.sha256(b'').digest() # Initial hash
	for blockNum in blockNums:
		block = blocks[blockNum]
		data = block['prev_hash']
		for transactionId in blockTransactions[blockNum]:
			transaction = transactions[(blockNum, transactionId)]
			if transaction['prev_root_hash'] != prev_root_hash:
				raise ValidationError('transaction %s of block number %s previous root hash mismatch' % (str(transactionId), str(blockNum)));
			data = data + transaction['tx_hash']
		data = data + block['root_hash']
		if hashlib.sha256(data).digest() != block['hash']:
			raise ValidationError('block hash is wrong at %s' % (str(blockNum),));
		prev_root_hash = block['root_hash']

	cursor.execute(
		"SELECT block_num, transaction_id, key, children, leaf, hash, value::text " +
		"FROM credereum_merkle_proof(%s::varbit[]) " +
		"ORDER BY block_num, transaction_id, key; ", ("{" + ",".join(keys) + "}",))
	prevBlockNum = None
	prevTransactionId = None
	tree = {}
	trees = {}
	result = []

	values = {}
	for key in keys:
		values[key] = None

	# Collect rows and associate them with trees
	row = cursor.fetchone()
	while row:
		if row[0] != prevBlockNum or row[1] != prevTransactionId:
			if tree:
				trees[(prevBlockNum, prevTransactionId)] = tree
				tree = {}
			prevBlockNum = row[0]
			prevTransactionId = row[1]
		if row[3]:
			children = row[3][1:-1].split(',')
		else:
			children = None
		node = {
			'children'	: children,
			'leaf'		: row[4],
			'hash'		: bytes(row[5]),
			'value'		: row[6],
			'orpham'	: True
		}
		tree[row[2]] = node;
		row = cursor.fetchone()
	cursor.close()
	if tree:
		trees[(prevBlockNum, prevTransactionId)] = tree
		tree = {}

	prevTree = {}
	for blockNum in blockNums:
		transactionTrees = {}
		for transactionId in blockTransactions[blockNum]:
			if not (blockNum, transactionId) in trees:
				raise ValidationError('missing proof for transaction %s of block number %s' % (str(transactionId), str(blockNum)));
			transactionTree = trees[(blockNum, transactionId)]
			make_tree(prevTree, transactionTree, '')
			check_tree_hash(transactionTree, '')
			check_for_orphams(transactionTree)
			if transactionTree['']['hash'] != transactions[(blockNum, transactionId)]['root_hash']:
				raise ValidationError('wrong root hash for transaction %s of block number %s' % (str(transactionId), str(blockNum)));
			transactionTrees[transactionId] = transactionTree

		if not (blockNum, None) in trees:
			raise ValidationError('missing proof for block number %s' % (str(blockNum),));

		blockTree = trees[(blockNum, None)]
		make_tree(prevTree, blockTree, '')
		check_tree_hash(blockTree, '')
		check_for_orphams(blockTree)

		if blockTree['']['hash'] != blocks[blockNum]['root_hash']:
			raise ValidationError('wrong root hash for block number %s' % (str(blockNum)));

		for key in keys:
			if key in blockTree:
				newValue = blockTree[key]['value']
			else:
				check_no_key_proof(blockTree, key)
				newValue = None

			oldValue = values[key]

			modifyTransactionId = None
			for transactionId in blockTransactions[blockNum]:
				transactionTree = transactionTrees[transactionId]
				if key in transactionTree:
					transactionValue = transactionTree[key]['value']
				else:
					check_no_key_proof(transactionTree, key)
					transactionValue = None
				if transactionValue != oldValue:
					if transactionValue == newValue:
						if modifyTransactionId is None:
							modifyTransactionId = transactionId
						else:
							raise ValidationError('both transactions %s and %s of block %s modify key %s' % (str(modifyTransactionId), str(transactionId), str(blockNum), key));
					else:
						raise ValidationError('value of key %s in transaction %s doesn\'t match block %s' % (key, str(transactionId), str(blockNum)));

			if oldValue != newValue:
				if modifyTransactionId is None:
					raise ValidationError('change key %s is not found in transactions of block number %s' % (key, str(blockNum)));
					transaction = transactions[(blockNum, modifyTransactionId)]
				pubkey = transaction['pubkey']
				x509 = crypto.X509()
				x509.set_pubkey(crypto.load_publickey(crypto.FILETYPE_PEM, pubkey))
				crypto.verify(
					x509,
					transaction['sign'],
					transaction['root_hash'] + transaction['prev_root_hash'],
					"sha256")

				result.append({
					'key'			: key,
					'block_num'		: blockNum,
					'transaction'	: modifyTransactionId,
					'new_value'		: newValue,
					'pubkey'		: pubkey
				})
			values[key] = newValue

		prevTree = blockTree
	return (blocks, result)
