#!/usr/bin/python

import binascii
import nacl.encoding
import nacl.secret
import sys

from nacl.hash import blake2b

# This must be kept secret, this is the combination to your safe
key = binascii.unhexlify('3f91942d47091eac32203d75188125fba55231ca78dc133f8dff6504bef51e2c')

box = nacl.secret.SecretBox(key)

if __name__ == '__main__':

	if len(sys.argv) < 2:
		print "ccnumber-encrypt.py encrypted-data"
		sys.exit(1)

	print box.decrypt(binascii.unhexlify(sys.argv[1][8:]))

