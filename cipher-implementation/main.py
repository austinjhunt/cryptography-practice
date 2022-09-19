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
    aes = AES(aes_key_size_bits=128)
    message = "Hello, my name is Austin Hunt."
    iv = os.urandom(16)
    ciphertext = aes.encrypt(
        plaintext=message,
        initialization_vector=iv
    )

    print('Encryption complete.')
    print(f'Cipher text: {ciphertext}')

    print('\n\n')

    decrypted = aes.decrypt(
        ciphertext=ciphertext,
        initialization_vector=iv
    )
    print(f'Decrypted: {decrypted}')
