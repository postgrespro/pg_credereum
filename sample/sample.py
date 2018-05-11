#!/usr/bin/env python3
import psycopg2
import random
import json
import hashlib
import sys
import binascii
import credereum
from OpenSSL import crypto

dbconn = psycopg2.connect("host='/tmp' dbname='postgres'")

value = 'abcdef'

keyFile = open("id_rsa", "r")
key = keyFile.read()
keyFile.close()
pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, key, None)

keyFile = open("id_rsa.pem", "r")
pubkey = keyFile.read()
keyFile.close()

for i in range(0, 100):
	cursor = dbconn.cursor()
	rowId = random.randint(1,10000)
	delta = random.randint(-49,50)
	if delta <= 0:
		delta = delta - 1

	cursor.execute("SELECT value FROM t WHERE id = %s FOR UPDATE", (rowId,))
	row = cursor.fetchone()
	if row:
		oldValue = row[0]
		if random.randint(1,4) == 1:
			sys.stdout.write("Perform delete: (id = %s)" % (rowId,))
			newValue = None
			cursor.execute("DELETE FROM t WHERE id = %s", (rowId,))
		else:
			newValue = oldValue + delta
			sys.stdout.write("Perform update: (id = %s, value = %s, oldValue = %s)" % (rowId, newValue, oldValue))
			cursor.execute("UPDATE t SET value = %s WHERE id = %s", (newValue, rowId))
	else:
		oldValue = None
		newValue = delta
		sys.stdout.write("Perform insert: (id = %s, value = %s)" % (rowId, newValue))
		cursor.execute("INSERT INTO t (id, value) VALUES (%s, %s)", (rowId, newValue))

	sys.stdout.write(" done\n")
	try:
		changeset = credereum.get_changeset(dbconn, True)
	except psycopg2.IntegrityError as e:
		print(e)
		cursor.close()
		dbconn.rollback()
		continue

	sys.stdout.write("Checking extracted changeset...")
	if oldValue is None:
		assert (not changeset['deletes']), 'We didn\'t perform deletes'
		assert (not changeset['updates']), 'We didn\'t perform updates'
		assert (len(changeset['inserts']) == 1), 'Should be exactly one insert'
		assert (sorted(list(changeset['inserts'][0]['value'].keys())) == ['id', 'value']), 'Row keys mismatch'
		assert (changeset['inserts'][0]['value']['id'] == rowId), 'Ids mismatch'
		assert (changeset['inserts'][0]['value']['value'] == newValue), 'Values mismatch'
	elif newValue is None:
		assert (not changeset['updates']), 'We didn\'t perform updates'
		assert (not changeset['inserts']), 'We didn\'t perform inserts'
		assert (len(changeset['deletes']) == 1), 'Should be exactly one delete'
		assert (sorted(list(changeset['deletes'][0]['value'].keys())) == ['id', 'value']), 'Row keys mismatch'
		assert (changeset['deletes'][0]['value']['id'] == rowId), 'Ids mismatch'
		assert (changeset['deletes'][0]['value']['value'] == oldValue), 'Values mismatch'
	else:
		assert (not changeset['deletes']), 'We didn\'t perform deletes'
		assert (len(changeset['updates']) == 1), 'Should be exactly one update'
		assert (not changeset['inserts']), 'We didn\'t perform inserts'
		assert (sorted(list(changeset['updates'][0]['oldValue'].keys())) == ['id', 'value']), 'Row keys mismatch'
		assert (sorted(list(changeset['updates'][0]['newValue'].keys())) == ['id', 'value']), 'Row keys mismatch'
		assert (changeset['updates'][0]['oldValue']['id'] == rowId), 'Ids mismatch'
		assert (changeset['updates'][0]['oldValue']['value'] == oldValue), 'Values mismatch: %s instead of %s' % (changeset['updates'][0]['oldValue']['value'], oldValue)
		assert (changeset['updates'][0]['newValue']['id'] == rowId), 'Ids mismatch'
		assert (changeset['updates'][0]['newValue']['value'] == newValue), 'Values mismatch'
	sys.stdout.write(" done\n")

	sys.stdout.write("Signing transaction...")
	sign = crypto.sign(pkey, changeset['hash'], "sha256")

	cursor.execute("SELECT credereum_sign_transaction(%s, %s);", (pubkey, psycopg2.Binary(sign)))
	cursor.close()
	sys.stdout.write(" done\n")

	sys.stdout.write("Committing...")
	dbconn.commit()
	sys.stdout.write(" done\n")

dbconn.close()

