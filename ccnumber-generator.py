#!/usr/bin/python

import binascii
import copy
import math
import nacl.encoding
import nacl.secret
import nacl.utils
import random

from nacl.hash import blake2b

# This must be kept secret, this is the combination to your safe
# key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
# print binascii.hexlify(key)
key = binascii.unhexlify('3f91942d47091eac32203d75188125fba55231ca78dc133f8dff6504bef51e2c')
auth_key = binascii.unhexlify('7a644823f7878926e8bf29740d7dd01dbc6bc9cabb7dd5278c38182c9689de7d')
box = nacl.secret.SecretBox(key)

prefixes_visa = ['4539', '4556', '4916', '4532', '4929', '4486', '4716']
prefixes_mastercard = ['51', '52', '53', '54', '55']
prefixes_amex = ['34', '37']


def generate_ccnumber(prefix, length):

	ccnumber = prefix

	# generate random digits up to the requested length
	while len(ccnumber) < (length - 1):
		ccnumber += str(random.choice(range(0, 10)))

	# calculate the control sum
	check_sum = 0
	cc_pos = 0

	ccnumber_reverse = ccnumber[::-1]

	while cc_pos < length - 1:

		odd = int(ccnumber_reverse[cc_pos]) * 2
		if odd > 9:
			odd -= 9

		check_sum += odd

		if cc_pos != (length - 2):
			check_sum += int(ccnumber_reverse[cc_pos + 1])

		cc_pos += 2

	# calculate the check digit
	check_digit = ((check_sum / 10 + 1) * 10 - check_sum) % 10
	ccnumber += str(check_digit)

	return ccnumber


def generate_card_numbers(prefixes, length, count):

	numbers = []

	while len(numbers) < count:

		ccnumber = random.choice(prefixes)
		numbers.append(generate_ccnumber(ccnumber, length))

	return numbers


def print_encrypted_ccnumbers(ccnumbers, max_count):

	for i in range(0,max_count):
		random.shuffle(ccnumbers)

		for c in ccnumbers:
			if random.random() < 0.5:
				h = blake2b(c, key=auth_key, encoder=nacl.encoding.HexEncoder)[0:8]
				print ("\\\\x" + h + binascii.hexlify(box.encrypt(c)) + "\t" + c)


ccnumbers = []

ccnumbers.extend(generate_card_numbers(prefixes_mastercard, 16, 100000))
ccnumbers.extend(generate_card_numbers(prefixes_visa, 16, 100000))
ccnumbers.extend(generate_card_numbers(prefixes_visa, 13, 10000))
ccnumbers.extend(generate_card_numbers(prefixes_amex, 15, 10000))

print_encrypted_ccnumbers(ccnumbers, 20)
