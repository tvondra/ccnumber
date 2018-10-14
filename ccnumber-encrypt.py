#!/usr/bin/python

import binascii
import nacl.encoding
import nacl.secret
import sys

from nacl.hash import blake2b

# This must be kept secret, this is the combination to your safe
key = binascii.unhexlify('3f91942d47091eac32203d75188125fba55231ca78dc133f8dff6504bef51e2c')
auth_key = binascii.unhexlify('7a644823f7878926e8bf29740d7dd01dbc6bc9cabb7dd5278c38182c9689de7d')

box = nacl.secret.SecretBox(key)

if __name__ == '__main__':

	if len(sys.argv) < 2:
		print "ccnumber-encrypt.py card-number"
		sys.exit(1)

	ccnumber = sys.argv[1]

	h = blake2b(ccnumber, key=auth_key, encoder=nacl.encoding.HexEncoder)[0:8]
	print ("\\\\x" + h + binascii.hexlify(box.encrypt(ccnumber)))
