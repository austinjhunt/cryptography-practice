"""
Austin Hunt
17 Sept 2022
Implementation of AES algorithm in Python
"""
import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest
from rijndael import Rijndael
from util import Util
from aescipher import AES

if __name__ == "__main__":
    # AES class parameterizes key sizes

    message = "Hello, my name is Austin Hunt."
    for i in range(3):
        keysize = {0: 128, 1: 192, 2: 256}[i]
        print(f'Testing with key size: {keysize} bits ')
        aes = AES(aes_key_size_bits=keysize)
        iv = os.urandom(16)
        print(f'The message is: {message}')
        print(f'The initialization vector is: {iv}')
        print('Beginning encryption')
        ciphertext = aes.encrypt(
            plaintext=message,
            initialization_vector=iv
        )
        print('Encryption complete.')
        print(f'The ciphertext is: {ciphertext}')
        print('\n')
        print(f'Decrypting using the same initialization vector {iv}')
        decrypted = aes.decrypt(
            ciphertext=ciphertext,
            initialization_vector=iv
        )
        print(f'Decrypted text: {decrypted}')
