import csv
import os
import json
import unittest
from aescipher import AES
INIT_VECTOR_FIXED_SIZE_BYTES = 16


class TestAESCipher(unittest.TestCase):
    """ Test cases for the 3 main key sizes available with AES cipher """

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), 'messages.json')) as f:
            self.messages = json.load(f)['messages']

    def check_each_message(self, cipher, init_vector):
        """ Reusable function to break each message encryption/decryption into a subtest"""
        for i, m in enumerate(self.messages):
            with self.subTest(i=i):
                ciphertext = cipher.encrypt(m, init_vector)
                decrypted = cipher.decrypt(ciphertext, init_vector)
                self.assertEqual(m, decrypted)

    def check_multiple_random_ivs(self, cipher):
        # test with multiple random init vectors
        for i in range(10):
            init_vector = os.urandom(INIT_VECTOR_FIXED_SIZE_BYTES)
            self.check_each_message(cipher, init_vector)

    #################### TEST KEY SIZES #########################
    def test_128(self):
        bits = 128
        print(f'Testing {bits} bit key size')
        cipher = AES(aes_key_size_bits=bits)
        self.check_multiple_random_ivs(cipher)

    def test_192(self):
        bits = 192
        print(f'Testing {bits} bit key size')
        cipher = AES(aes_key_size_bits=bits)
        self.check_multiple_random_ivs(cipher)

    def test_256(self):
        bits = 256
        print(f'Testing {bits} bit key size')
        cipher = AES(aes_key_size_bits=bits)
        self.check_multiple_random_ivs(cipher)
    #################### TEST KEY SIZES #########################


# class TestAVS(unittest.TestCase):
#     def setUp(self):
#         with open(os.path.join(os.path.dirname(__file__), 'aesavstestdata.csv')) as f:
#             reader = csv.reader(f)
#             next(reader)
#             self.keysize_128_tests = [l for l in reader if l[0] == '128']
#             self.keysize_192_tests = [l for l in reader if l[0] == '192']
#             self.keysize_256_tests = [l for l in reader if l[0] == '256']

#     def test_128bit_keysize(self):
#         aes = AES(aes_key_size_bits=128)
#         aes.set_master_key(b'0000000000000000')
#         for t in self.keysize_128_tests:
#             plaintextoriv, ct = t[1], t[2]
#             iv, plaintext = plaintextoriv[16:], plaintextoriv[:16]
#             plaintext = plaintext.encode('utf-8')
#             iv = iv.encode('utf-8')
#             ct = ct.encode('utf-8')
#             ciphertext = aes.encrypt(
#                 plaintext=plaintext,
#                 initialization_vector=iv
#             )
#             self.assertEqual(
#                 ct, ciphertext
#             )

#     def test_192bit_keysize(self):
#         aes = AES(aes_key_size_bits=192)
#         aes.set_master_key(b'000000000000000000000000')
#         for t in self.keysize_192_tests:
#             plaintextoriv, ct = t[1], t[2]
#             iv, plaintext = plaintextoriv[16:], plaintextoriv[:16]
#             plaintext = plaintext.encode('utf-8')
#             iv = iv.encode('utf-8')
#             ct = ct.encode('utf-8')
#             ciphertext = aes.encrypt(
#                 plaintext=plaintext,
#                 initialization_vector=iv
#             )
#             self.assertEqual(
#                 ct, ciphertext
#             )

#     def test_256bit_keysize(self):
#         aes = AES(aes_key_size_bits=192)
#         aes.set_master_key(b'00000000000000000000000000000000')
#         for t in self.keysize_256_tests:
#             plaintextoriv, ct = t[1], t[2]
#             iv, plaintext = plaintextoriv[16:], plaintextoriv[:16]
#             plaintext = plaintext.encode('utf-8')
#             iv = iv.encode('utf-8')
#             ct = ct.encode('utf-8')
#             ciphertext = aes.encrypt(
#                 plaintext=plaintext,
#                 initialization_vector=iv
#             )
#             self.assertEqual(
#                 ct, ciphertext
#             )
