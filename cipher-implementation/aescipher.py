"""
Austin Hunt
17 Sept 2022
Implementation of AES algorithm in Python

Credit to BoppreH on Github: https://github.com/boppreh
Fantastic reference for AES implementation in Python

"""
import os
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest
from util import Util
from scheduler import KeyScheduler


class AES(Util):
    def __init__(self, aes_key_size_bits: int = 128, master_key=None):
        super().__init__()

        self.aes_key_size = aes_key_size_bits // 8
        self.hmac_key_size = 128 // 8
        self.hmac_size = 256 // 8
        self.salt_size = 128 // 8
        self.block_size = 16
        self.iv_size = self.block_size
        self.num_rounds = {128: 10, 192: 12, 256: 14}[aes_key_size_bits]
        if not master_key:
            self.master_key = self.generate_random_aes_key()
            # print(f'Master key generated: {self.master_key}')
            self.key_scheduler = KeyScheduler()
            self.round_keys = self.key_scheduler.get_key_expansion(
                base_key=self.master_key,
                key_columns=self._convert_byte_array_to_state_matrix(
                    self.master_key),
                num_rounds=self.num_rounds
            )
            # print(f'{len(self.round_keys)} round keys generated.')
            # for i, r in enumerate(self.round_keys):
            # print(f'Round key {i} length = {len(r)}')

    def generate_random_aes_key(self):
        """ Generate a random AES base key using the bytes size self.aes_key_size """
        return os.urandom(self.aes_key_size)

    def set_master_key(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')
        self.master_key = key
        self.key_scheduler = KeyScheduler()
        self.round_keys = self.key_scheduler.get_key_expansion(
            base_key=self.master_key,
            key_columns=self._convert_byte_array_to_state_matrix(
                self.master_key),
            num_rounds=self.num_rounds
        )
        # print(f'{len(self.round_keys)} round keys generated.')
        # for i, r in enumerate(self.round_keys):
        # print(f'Round key {i} length = {len(r)}')

    def _add_round_key(self, state, round_key):
        """
        each byte of the state is combined with a byte of the round key using bitwise xor.
        """
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]

    def xtime(self, a: bytes):
        """ xtime operation documented here, used for mixcolumn operation
        https://www.usenix.org/legacy/publications/library/proceedings/cardis02/full_papers/valverde/valverde_html/node12.html
        xtime(a) is simply a shift of byte a followed conditionally by an xor of two bytes

        also demonstrated here in c: https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c

        According to https://groups.google.com/g/sci.crypt/c/Exrm5l0WePY?pli=1
        Mixcolumn, which is a polynomial multiplication, can be represented as multiplication of each
        column of the cipher state by a circulant matrix with coefficients 02, 03, 01, and 01 in GF(2^8).
        Note that x*02 is just xtime(x). x * 03 = xtime(x) + x.

        """
        if a & 0x80:  # bitwise AND
            return ((a << 1) ^ 0x1B) & 0xFF
        else:
            return a << 1

    def _shift_rows(self, state: list):
        """
        a transposition step where the last three rows of the state are shifted
        cyclically a certain number of steps during encryption.
        The first row is left unchanged. Each byte of the second row is shifted
        one to the left. Similarly, the third and fourth rows are shifted by offsets
        of two and three respectively.
        """
        # Using this iteration fails even though the same assignments are made.
        # Ultimately because of timing; multiple assignment in this case is meaningful.
        # As indicated here: ht-hand side is always evaluated fully before doing the actual setting of variables. So,
        # the right side in multi-assignment is evaluated fully before the assignment is made.
        # We need that to happen. We don't want to assign a value to state[0][3] and have a next
        # assignment use that new value, which happens in iteration.
        # shift = 0
        # for r in range(1,4):
        #     shift += 1
        #     for c in range(4):
        #         state[c][r] = state[(c + shift) % 4][r]
        state[0][1], state[1][1], state[2][1], state[3][1] = state[1][1], state[2][1], state[3][1], state[0][1]
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[3][3], state[0][3], state[1][3], state[2][3]

    def _inverse_shift_rows(self, state: list):
        """
        Invert row shift applied by self._shift_rows
        a transposition step where the last three rows of the state are shifted
        cyclically a certain number of steps during decryption.
        The first row is left unchanged. Each byte of the second row is shifted
        one to the right. Similarly, the third and fourth rows are shifted by
        offsets of two and three respectively.
        """
        # Using this iteration fails even though the same assignments are made.
        # Ultimately because of timing; multiple assignment in this case is meaningful.
        # As indicated here: ht-hand side is always evaluated fully before doing the actual setting of variables. So,
        # the right side in multi-assignment is evaluated fully before the assignment is made.
        # We need that to happen. We don't want to assign a value to state[0][3] and have a next
        # assignment use that new value, which happens in iteration.
        # shift = 0
        # for r in range(1,4):
        #     shift += 1
        #     for c in range(4):
        #         state[c][r] = state[(c - shift) % 4][r]
        state[0][1], state[1][1], state[2][1], state[3][1] = state[3][1], state[0][1], state[1][1], state[2][1]
        state[0][2], state[1][2], state[2][2], state[3][2] = state[2][2], state[3][2], state[0][2], state[1][2]
        state[0][3], state[1][3], state[2][3], state[3][3] = state[1][3], state[2][3], state[3][3], state[0][3]

    def mix_single_column(self, a):
        """ Mix one single column of a state matrix;
        Implemention coming directly from
        Section 4.1.2 in The Design of Rijndael shown in README
        """
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]  # first row
        for i in range(4):
            m = u if (i + 1) % 4 == 0 else a[i + 1]
            v = a[i] ^ m
            v = self.xtime(v)
            a[i] = a[i] ^ t ^ v

    def mix_columns(self, state: list):
        """ Handle the mix columns step of an AES round
        a linear mixing operation which operates on the columns of the state,
        combining the four bytes in each column. Provides diffusion in the AES cipher.
        """
        for i in range(4):
            self.mix_single_column(state[i])

    def _inverse_mix_columns(self, state: list):
        """ Invert the column mixing; implementation directly from
        section 4.1.3 in The Design of Rijndael, shown in README.
        KEY NOTE from that section:
        ... InvMixColumns can be implemented as a simple preprocessing step, followed by a MixColumns step.
        """
        for i in range(4):
            a = state[i]  # a is a column
            u = self.xtime(self.xtime(a[0] ^ a[2]))
            v = self.xtime(self.xtime(a[1] ^ a[3]))
            a[0] ^= u
            a[1] ^= v
            a[2] ^= u
            a[3] ^= v

        self.mix_columns(state)

    def decrypt(self, ciphertext, initialization_vector):
        """
        Decrypt ciphertext using the initialization vector used by encryption.

        The AES algorithm requires that the IV size must be 16 bytes (128 bits)
        """
        assert len(initialization_vector) == 16

        decrypted_blocks = []
        previous = initialization_vector
        # print(f'starting prev = {previous}')
        blocks = self._split_into_blocks(ciphertext)
        # print(f'Split ciphertext into {len(blocks)} blocks for decryption')
        for ciphertext_block in blocks:
            decrypted_block = self.xor_bytes(
                previous, self.decrypt_block(ciphertext_block)
            )
            # print(f'Decrypted block: {decrypted_block}')
            decrypted_blocks.append(decrypted_block)
            previous = ciphertext_block
        return self._remove_padding(b''.join(decrypted_blocks)).decode('utf-8')

    def decrypt_block(self, ciphertext):
        """
        Decrypt single 16 byte block (128 bits) of cipher text
        """
        assert len(ciphertext) == 16

        # Step 1: Get the 4x4 state matrix from the cipher text block
        cipher_state = self._convert_byte_array_to_state_matrix(ciphertext)

        # Step 2: Add round key for current / initial round
        self._add_round_key(cipher_state, self.round_keys[-1])

        # invert the row shift and byte substitutions since
        # encryption ends with sub bytes and then shift rows
        self._inverse_shift_rows(cipher_state)
        self._inverse_substitute_bytes(cipher_state)

        for i in range(self.num_rounds - 1, 0, -1):
            self._add_round_key(cipher_state, self.round_keys[i])
            self._inverse_mix_columns(cipher_state)
            self._inverse_shift_rows(cipher_state)
            self._inverse_substitute_bytes(cipher_state)

        # Finish by adding (xoring) round key
        self._add_round_key(cipher_state, self.round_keys[0])

        return self._convert_state_matrix_to_byte_array(cipher_state)

    def _get_key_iv(self, password, salt, workload=100000):
        """
        Introduce some randomness with an initialization vector.
        Purpose of IV is to to achieve semantic security,
        a property whereby repeated usage of the scheme under the same key
        does not allow an attacker to infer relationships between
        (potentially similar) segments of the encrypted message.

        Stretches the password and extracts an AES key, an HMAC key and an AES
        initialization vector.
        """
        stretched = pbkdf2_hmac('sha256', password, salt,
                                workload, self.aes_key_size + self.iv_size + self.hmac_key_size)
        aes_key, stretched = stretched[:self.aes_key_size], stretched[self.aes_key_size:]
        hmac_key, stretched = stretched[:self.hmac_key_size], stretched[self.hmac_key_size:]
        iv = stretched[:self.iv_size]
        return aes_key, hmac_key, iv

    def _encrypt_block(self, plaintext):
        """ Encrypt single 16 byte block (128 bits) of plaintext """
        # Ensure the plaintext length is actually the correct block size
        assert len(plaintext) == 16
        # step 1: convert plaintext to "state" 4x4 matrix
        plaintext_state = self._convert_byte_array_to_state_matrix(plaintext)

        # step 2: add (xor) round key for current / initial round
        self._add_round_key(plaintext_state, self.round_keys[0])

        # Do rounds, but don't do final round yet. Final round does not include mix columns.
        for i in range(1, self.num_rounds):  # will total num rounds - 1 iterations
            self._substitute_bytes(plaintext_state)
            self._shift_rows(plaintext_state)
            self.mix_columns(plaintext_state)
            self._add_round_key(plaintext_state, self.round_keys[i])

        self._substitute_bytes(plaintext_state)
        self._shift_rows(plaintext_state)
        self._add_round_key(plaintext_state, self.round_keys[-1])

        return self._convert_state_matrix_to_byte_array(plaintext_state)

    def encrypt(self, plaintext, initialization_vector):
        """ Utility method for encryption """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        elif isinstance(plaintext, int):
            plaintext = str(plaintext).encode('utf-8')

        # step 1: key expansion into 128 bit round keys / blocks - already done at AES instantiation

        # add padding; won't do anything if no padding needed
        plaintext = self._add_padding(plaintext)

        # initial round key addition; each byte of the state is combined with a byte of the round key using bitwise xor.
        encrypted_blocks = []
        prev = initialization_vector
        blocks = self._split_into_blocks(plaintext)
        # print(f'Split plaintext into {len(blocks)} blocks for encryption')
        for plaintext_block in blocks:
            encrypted_block = self._encrypt_block(
                self.xor_bytes(
                    plaintext_block,
                    prev
                )
            )
            encrypted_blocks.append(encrypted_block)
            prev = encrypted_block
        return b''.join(encrypted_blocks)
