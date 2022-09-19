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
                self.assertEquals(m, decrypted)

    def check_multiple_random_ivs(self, cipher):
        # test with multiple random init vectors
        for i in range(10):
            init_vector = os.urandom(INIT_VECTOR_FIXED_SIZE_BYTES)
            self.check_each_message(cipher, init_vector)

    #################### TEST KEY SIZES #########################
    def test_128(self):
        bits = 128
        cipher = AES(aes_key_size_bits=bits)
        self.check_multiple_random_ivs(cipher)

    def test_192(self):
        bits = 192
        cipher = AES(aes_key_size_bits=bits)
        self.check_multiple_random_ivs(cipher)

    def test_256(self):
        bits = 256
        cipher = AES(aes_key_size_bits=bits)
        self.check_multiple_random_ivs(cipher)
    #################### TEST KEY SIZES #########################

class TestMonteCarlo(unittest.TestCase):
    pass