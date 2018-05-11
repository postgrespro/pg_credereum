#!/usr/bin/env python3
import psycopg2
import random
import json
import hashlib
import sys
import binascii
import credereum
from OpenSSL import crypto
from web3 import Web3, HTTPProvider, IPCProvider
import json
import argparse

parser = argparse.ArgumentParser(description='Get history proof for some ids.')
parser.add_argument('ids', metavar='N', type=int, nargs='+',
					help='an integer for the accumulator')
args = parser.parse_args()

def get_ethereum_hashes(contractAddress):
	web3 = Web3(HTTPProvider())
	with open('../hts_eth/HashStorage.js', 'r') as abi_definition:
		contract = json.load(abi_definition)
	contracts = contract['contracts']
	# The full key is written as <contract file path> + ':' + <contract name>, 
	# and we don't know the file path, so search by the contract name.
	contractName = next(i for i in contracts.keys() if ":HashStorage" in i)
	abi = contracts[list(contracts.keys())[0]]['abi']

	contract = web3.eth.contract(abi = abi, address = web3.toChecksumAddress(contractAddress))
	lastId = contract.functions.getLastHashId().call()
	result = []
	for i in range(1, lastId + 1):
		h = contract.functions.getHash(i).call()
		# web3.toHex trims leading zeroes, so we can't use it
		result.append(binascii.unhexlify("{0:#066x}".format(h)[2:]))
	return result;

# Get the contract address from pg_credereum configuration
dbconn = psycopg2.connect("dbname='postgres' host='/tmp'")
cur = dbconn.cursor()
cur.execute("show pg_credereum.eth_contract_addr;")
contractAddress = cur.fetchall()[0][0]

ethereumHashes = get_ethereum_hashes(contractAddress)

# Request the transaction history for requested ids
encodedKeys = []
keysMap = {}
for id in args.ids:
	key = ('public.t', id)
	encodedKey = credereum.get_key(key[0], key[1])
	encodedKeys.append(encodedKey)
	keysMap[encodedKey] = key

(blocks, history) = credereum.get_history_proof(dbconn, encodedKeys)

i = 0
lastConfirmedBlock = 0
for h in ethereumHashes:
	while i < len(blocks):
		block = blocks[i]
		if block['hash'] == h:
			lastConfirmedBlock = block['block_num']
			break
		i = i + 1
	if i == len(blocks):
		raise ValidationError('block hashes mismatch with trusted storage: %s' % (binascii.hexlify(h),));
print("Last confirmed block is %s" % (str(lastConfirmedBlock),))

prevBlockNum = None
prevTransaction = None
prevPubkey = None

for row in history:
	if prevBlockNum != row['block_num'] or prevTransaction != row['transaction']:
		if prevPubkey is not None:
			print("\tpubkey: %s" % (prevPubkey,))
			print('')
		if row['block_num'] > lastConfirmedBlock:
			print("*** Unconfirmed block ***")
		print("block number: %s, transaction: %s" % (str(row['block_num']), str(row['transaction'])))
	key = keysMap[row['key']]
	print("\t(%s, %s): %s" % (key[0], key[1], row['new_value']))
	prevBlockNum = row['block_num']
	prevTransaction = row['transaction']
	prevPubkey = row['pubkey']

if prevPubkey is not None:
	print("\tpubkey: %s" % (prevPubkey,))
	print('')

dbconn.close()
