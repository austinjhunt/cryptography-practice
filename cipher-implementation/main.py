"""
Austin Hunt
17 Sept 2022
Implementation of AES algorithm in Python
"""
import os
from typing import List
from functools import reduce
from hashlib import pbkdf2_hmac
from hmac import new as new_hmac, compare_digest


class Util:
    def xor_bytes(self, *arg: bytes) -> bytes:
        # all args must have the same length
        assert len({len(x) for x in arg}) == 1
        def xor_fun(x, y): return x ^ y
        return bytes(reduce(xor_fun, byt3s) for byt3s in zip(*arg))


class Rijndael:
    def __init__(self):
        # From wikipedia: https://en.wikipedia.org/wiki/Rijndael_S-box
        # The S-box maps an 8-bit input, c, to an 8-bit output, s = S(c).
        # Used by AES encryption process, key scheduling/expansion so just subclass this.
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
        ]

        self.inv_sbox = [
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
        ]


class KeyScheduler(Rijndael, Util):
    """ class for expanding a base key through key scheduling.
    Produces a key for each round of AES (where number of rounds is determined
    from key size). Key expansion explanation reference: https://www.youtube.com/watch?v=rmqWaktEpcw
    """

    def __init__(self):
        super().__init__()

    def set_round_constants(self, num_rounds=None):
        self.rcon = []

        def recurse(constants_to_generate: int = 10):
            """ Round constants are generated recursively
            rc(1) = 1
            rc(i) = 2 * rc(i - 1) if rc(i-1) < 0x80
            rc(i) = (2 * rc(i-1)) xor 0x11B  if rc(i-1) >= 0x80
            """
            if constants_to_generate == 1:
                self.rcon.append(0x00)
                self.rcon.append(0x01)
                return 0x01
            else:
                next_result = recurse(constants_to_generate - 1)
                if next_result < 0x80:
                    result = 2 * next_result
                else:
                    result = (2 * next_result) ^ 0x11B
                self.rcon.append(result)
                return result
        recurse(constants_to_generate=num_rounds)
        # self.rcon = [x.to_bytes(4, 'little') for x in self.rcon]
        return self.rcon

    def rot_word(self, word: bytes) -> bytes:
        """
        apply the RotWord transformation explained to 4 bytes/32bits
        https://youtu.be/rmqWaktEpcw?t=345
        Second byte becomes first, third becomes second, fourth becomes third, first becomes fourth
        via mod operation.
        """
        assert len(word) == 4
        result = bytes((word[(i + 1) % 4] for i in range(4)))
        return result

    def inv_rot_word(self, word: bytes) -> bytes:
        '''
        apply the inverse of the RotWord transformation to 4 bytes/32bits
        First byte becomes second, second becomes third, third becomes fourth, fourth becomes first
        '''
        assert len(word) == 4
        result = bytes((word[(i - 1) % 4] for i in range(4)))
        return result

    def sub_word(self, word: bytes) -> bytes:
        """
        Quite easy; apply the AES S-Box AKA the Rijndael S-box
        https://en.wikipedia.org/wiki/Rijndael_S-box
        to each of the bytes of the 4-byte word. (32 bits)
        We index into the sbox byte array for each byte
        in this 4 byte word. The indexing first converts the input byte to an int N
        then pulls the Nth index value from sbox as an integer. We do this for each byte
        and then convert the list of ints back into a bytes object which is the substitution value.
        """
        assert len(word) == 4
        sub = bytes((self.sbox[w] for w in word))
        return sub

    def inv_sub_word(self, word: bytes) -> bytes:
        '''
        Quite easy; apply the inverse of the AES S-Box AKA the Rijndael S-box
        https://en.wikipedia.org/wiki/Rijndael_S-box
        to each of the bytes of the 4-byte word. (32 bits)
        We index into the inv_sbox byte array for each byte
        in this 4 byte word. The indexing first converts the input byte to an int N
        then pulls the Nth index value from sbox as an integer. We do this for each byte
        and then convert the list of ints back into a bytes object which is the substitution value.
        '''
        assert len(word) == 4
        sub = bytes((self.inv_sbox[w] for w in word))
        print(
            f'inverse substitution 32 bit word for 32 word input {word} is {sub}')
        return sub

    def reverse_key_schedule(self, round_key: bytes, aes_round: int):
        """
        reverse the AES key schedule, using a single round_key.
        """
        round_key_len = len(round_key)
        # all round keys should be 128 bits; 16 bytes
        assert round_key_len == 16
        for i in range(aes_round - 1, -1, -1):
            a2 = round_key[0:4]
            b2 = round_key[4:8]
            c2 = round_key[8:12]
            d2 = round_key[12:16]

            d1 = self.xor_bytes(d2, c2)
            c1 = self.xor_bytes(c2, b2)
            b1 = self.xor_bytes(b2, a2)
            a1 = self.xor_bytes(a2, self.rot_word(
                self.sub_word(d1)), self.rcon[i])
            round_key = a1 + b1 + c1 + d1

        return round_key

    def get_length_of_key_in_32_bit_words(self, num_key_bits: int = 128):
        """ Given the length in bits of the base AES key,
        return the number of 32 bit words / chunks to break the key into. """
        result = num_key_bits // 32
        print(
            f'Splitting key of size {num_key_bits} bits into {result} 32 bit chunks')
        return result

    def get_num_round_keys(self, num_key_bits: int = 128):
        """ Return the number of round keys that need to be produced
        based on key size. """
        return {128: 11, 192: 13, 256: 15}[num_key_bits]

    def initialize_32_bit_word_chunks_of_key(self, base_key: bytes, num_round_keys: int = 11, length_of_key_in_32_bit_words: int = 4):
        """ Initialize round keys; should be 4 32bit words for each round; initial value is None for each """
        _32_bit_word_chunks_of_key = [None for _ in range(num_round_keys * 4)]
        for i in range(length_of_key_in_32_bit_words):
            # first round key is first 32 bits, second is next 32 bits, etc.
            _32_bit_word_chunks_of_key[i] = base_key[i * 4: (i + 1) * 4]
        return _32_bit_word_chunks_of_key

    def key_schedule(self, base_key: bytes) -> List[bytes]:
        """ Expand provided AES base key into N round keys,
        where N is determined from length of key: N=11,13,15 for AES-128,192,256 respectively.
        Key schedule doc referenced: https://en.wikipedia.org/wiki/AES_key_schedule
         """
        num_key_bits = len(base_key) * 8

        assert num_key_bits in {128, 192, 256}

        length_of_key_in_32_bit_words = self.get_length_of_key_in_32_bit_words(
            num_key_bits)

        num_round_keys = self.get_num_round_keys(num_key_bits)
        self.num_rounds = num_round_keys - 1
        self.set_round_constants()

        # the 32 bits words of the expanded key
        _32_bit_word_chunks_of_key = self.initialize_32_bit_word_chunks_of_key(
            base_key, num_round_keys, length_of_key_in_32_bit_words)

        # def first_word_of_round_key(i):
        #     return i % length_of_key_in_32_bit_words == 0

        # def get_first_word_of_round_key(i):
        #     """ Calculate out"""
        #     previous_corresponding_word = _32_bit_word_chunks_of_key[i -
        #                                                              length_of_key_in_32_bit_words]
        #     previous_word = _32_bit_word_chunks_of_key[i-1]
        #     rotate_then_sub_result = self.sub_word(
        #         self.rot_word(previous_word))
        #     current_round_constant = self.rcon[i //
        #                                        length_of_key_in_32_bit_words - 1]
        #     xor_result = self.xor_bytes(
        #         previous_corresponding_word,
        #         rotate_then_sub_result,
        #         current_round_constant
        #     )
        #     return xor_result

        # def middle_word_of_round_key(i):
        #     return length_of_key_in_32_bit_words > 6 and i % length_of_key_in_32_bit_words == 4

        # def get_middle_word_of_round_key(i):
        #     previous_corresponding_word = _32_bit_word_chunks_of_key[i -
        #                                                              length_of_key_in_32_bit_words]
        #     previous_word = _32_bit_word_chunks_of_key[i-1]
        #     sub_previous_word = self.sub_word(previous_word)
        #     xor_result = self.xor_bytes(
        #         previous_corresponding_word,
        #         sub_previous_word)
        #     return xor_result

        # def get_(i):
        #     previous_corresponding_word = _32_bit_word_chunks_of_key[i -
        #                                                              length_of_key_in_32_bit_words]
        #     previous_word = _32_bit_word_chunks_of_key[i - 1]
        #     xor_result = self.xor_bytes(
        #         previous_corresponding_word,
        #         previous_word
        #     )
        #     return xor_result

        N = length_of_key_in_32_bit_words
        W = _32_bit_word_chunks_of_key
        K = base_key
        R = num_round_keys

        # for i in range 0 ... 4 * R - 1
        # W[i] =  {
        # K[i]                                          if i < N
        # W[i-N] xor Sub(Rot(W[i-1])) xor Rcon[i/N]     if i >= N and i mod N = 0
        # W[i-N] xor Sub(W[i-1])                        if i >= N, i > 6, and i mod N =4
        # W[i-N] xor W[i-1]
        keys = []
        for i in range(N, 4 * R):
            if i >= N and i % N == 0:
                W[i] = self.xor_bytes(
                    W[i-N],
                    self.sub_word(self.rot_word(W[i-1])),
                    self.rcon[i // N - 1]
                )
            elif i >= N and i > 6 and i % N == 4:
                W[i] = self.xor_bytes(
                    W[i-N],
                    self.sub_word(W[i-1])
                )
            else:
                W[i] = self.xor_bytes(
                    W[i-N], W[i-1]
                )
            if not isinstance(W[i], bytes):
                W[i] = bytes(W[i])
        keys = [b''.join(W[i * 4 + j] for j in range(4)) for i in range(R)]
        return keys

    def get_key_expansion_2(self, base_key, key_columns, num_rounds):
        """
        Expand AES base key into num_rounds + 1 round keys.
        Alternative approach to key expansion from boppreh / aes at
        https://github.com/boppreh/aes/blob/d6857518fa95f08352a250242b0cf21d2544e470/aes.py#L190
        """
        num_rows = len(base_key) // 4
        i = 1
        rcon = self.set_round_constants(num_rounds=num_rounds)
        while len(key_columns) < (num_rounds + 1) * 4:
            word = list(key_columns[-1])
            if len(key_columns) % num_rows == 0:
                # new row. circular shift.
                word.append(word.pop(0))
                # Map to S-BOX.
                word = [self.sbox[b] for b in word]
                # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
                word[0] ^= rcon[i]
                i += 1
            elif len(base_key) == 32 and len(key_columns) % num_rows == 4:
                # Run word through S-box in the fourth iteration when using a
                # 256-bit key.
                word = [self.sbox[b] for b in word]

            # XOR with equivalent word from previous iteration.
            word = self.xor_bytes(word, key_columns[-num_rows])
            key_columns.append(word)

        # Group key words in 4x4 byte matrices.
        return [key_columns[4*i: 4*(i+1)] for i in range(len(key_columns) // 4)]


class AES(Rijndael, Util):
    def __init__(self,
                 aes_key_size_bits: int = 128,
                 hmac_key_size_bits: int = 128,
                 hmac_size_bits: int = 256,
                 salt_size_bits: int = 128):
        super().__init__()
        # store sizes as bytes
        self.aes_key_size = aes_key_size_bits // 8
        self.hmac_key_size = hmac_key_size_bits // 8
        self.hmac_size = hmac_size_bits // 8
        self.salt_size = salt_size_bits // 8
        self.block_size = 16
        self.iv_size = self.block_size
        self.num_rounds = {128: 10, 192: 12, 256: 14}[aes_key_size_bits]

    def generate_random_aes_key(self):
        """ Generate a random AES base key using the bytes size self.aes_key_size """
        return os.urandom(self.aes_key_size)

    def xor_bytes(self, a, b):
        """ Returns a new byte array with the elements xor'ed. """
        return bytes(i ^ j for i, j in zip(a, b))

    def get_key_expansion(self):
        print(f'Getting key expansion')
        key_expander = KeyScheduler()
        round_keys = key_expander.key_schedule(base_key=self.base_key)
        print(f'({len(round_keys)}) round keys obtained via expansion')
        self.round_keys = round_keys
        return round_keys

    def _add_padding(self, plaintext):
        """ Pad plaintext to a multiple of 128 bits / 16 bytes to align
        with fixed 16 byte block size """
        padding_needed = self.block_size - (len(plaintext) % self.block_size)
        print(f'Adding {padding_needed} bytes of padding to plaintext')
        padded = plaintext + bytes([padding_needed] * padding_needed)
        # Use the actual value of the needed padding as the padding
        # so that it can be removed easily by getting the last value
        # that tells how many bytes need to be removed
        return padded

    def _remove_padding(self, plaintext):
        """
        Removes padding if any; since each padding byte actually IS the length
        of the total padding that was added to end, just get last value
        """
        print(f'Checking for padding on plaintext: {plaintext}')
        padding_added = plaintext[-1]
        print(f'Padding added: {padding_added}')
        assert padding_added > 0
        message = plaintext[:-padding_added]
        padding = plaintext[-padding_added:]
        print(f'Message={message}')
        print(f'Padding={padding}')
        assert all(p == padding_added for p in padding)
        return message

    def _split_into_blocks(self, plaintext):
        """ split plaintext into 128 bit / 16 byte blocks. Use padding if not an even split """
        if len(plaintext) % self.block_size != 0:
            plaintext = self._add_padding(plaintext)
        blocks = [plaintext[i: i + self.block_size]
                  for i in range(0, len(plaintext), self.block_size)]
        return blocks

    def _convert_byte_array_to_state_matrix(self, word: bytes):
        """
        AES operates on a 4 × 4 column-major order array of bytes, termed the state
        Convert a given 16-byte word into a 4x4 matrix
        """
        print(f'Converting byte array {word} to 4 x 4 matrix')
        matrix = []
        for i in range(0, len(word), 4):
            matrix.append(list(word[i: i + 4]))
        return matrix

    def _convert_state_matrix_to_byte_array(self, matrix: list):
        """ Convert a 4x4 state matrix back into a byte array  """
        flattened = sum(matrix, [])  # easy way to flatten 2d array
        flattened_bytes = bytes(flattened)
        return flattened_bytes

    def _add_round_key(self, state, round_key):
        """
        each byte of the state is combined with a byte of the round key using bitwise xor.
        """
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i][j]

    def _substitute_bytes(self, state: list):
        """ Use the Rijndael S-box for byte substitution within the current state matrix """
        for i in range(4):
            for j in range(4):
                state[i][j] = self.sbox[state[i][j]]
        return state

    def _inverse_substitute_bytes(self, state: list):
        """ Use the inverse Rijndael S-box for inverse byte substitution within current state matrix """
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]
        return state

    def _shift_rows(self, state: list):
        """
        a transposition step where the last three rows of the state are shifted
        cyclically a certain number of steps during encryption.
        The first row is left unchanged. Each byte of the second row is shifted
        one to the left. Similarly, the third and fourth rows are shifted by offsets
        of two and three respectively.
        """
        for r in range(1, 4):
            for c in range(0, 4):
                state[c][r] = state[(c + 1) % 4][r]
        return state

    def _inverse_shift_rows(self, state: list):
        """
        Invert row shift applied by self._shift_rows
        a transposition step where the last three rows of the state are shifted
        cyclically a certain number of steps during decryption.
        The first row is left unchanged. Each byte of the second row is shifted
        one to the right. Similarly, the third and fourth rows are shifted by
        offsets of two and three respectively.
        """
        for r in range(1, 4):
            for c in range(0, 4):
                state[c][r] = state[(c - 1) % 4][r]

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
            a[i] = a[i] ^ v ^ t

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

    def decrypt(self, key, ciphertext, workload=100000):
        """
        Decrypts ciphertext using the AES key, as well as HMAC to verify integrity and
        PBKDF2, which is a simple cryptographic key derivation function, which is
        resistant to dictionary attacks and rainbow table attacks.
        The exact algorithm is specified in the module docstring.

        Ciphertext must be made of full 16-byte blocks.

        Ciphertext must also be at least 32 bytes long (16 byte salt + 16 byte block). To
        encrypt or decrypt single blocks use `AES(key).decrypt_block(ciphertext)`.
        """

        assert len(ciphertext) % 16 == 0
        assert len(ciphertext) >= 32

        if isinstance(key, str):
            key = key.encode('utf-8')
        hmac, ciphertext = ciphertext[:self.hmac_size], ciphertext[self.hmac_size:]
        salt, ciphertext = ciphertext[:self.salt_size], ciphertext[self.salt_size:]
        self.base_key, self.hmac_key, self.iv = self._get_key_iv(
            password=key,
            salt=salt,
            workload=workload)
        print(f'base key for decryption: {self.base_key}')
        print(f'IV for decryption: {self.iv}')
        expected_hmac = new_hmac(
            self.hmac_key, salt + ciphertext, 'sha256').digest()
        assert compare_digest(
            hmac, expected_hmac), 'Ciphertext corrupted or tampered.'
        return self._decrypt_util(ciphertext=ciphertext, initialization_vector=self.iv)

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

    def _decrypt_util(self, ciphertext, initialization_vector):
        """
        Decrypt ciphertext using the initialization vector used by encryption
        """
        assert len(initialization_vector) == 16

        decrypted_blocks = []
        previous = initialization_vector
        print(f'starting prev = {previous}')
        blocks = self._split_into_blocks(ciphertext)
        print(f'Split ciphertext into {len(blocks)} blocks for decryption')
        for ciphertext_block in blocks:
            decrypted_block = self.xor_bytes(
                previous, self.decrypt_block(ciphertext_block)
            )
            print(f'Decrypted block: {decrypted_block}')
            decrypted_blocks.append(decrypted_block)
            previous = ciphertext_block
        return self._remove_padding(b''.join(decrypted_blocks))

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

    def encrypt(self, key, plaintext):
        """ Encrypt plaintext with provided AES key using AES algorithm
        AES provides only confidentiality.
        It does not provide integrity. To maintain integrity (preventing tampering)
        use HMAC, an algorithm for producing a message authentication code, documented here: https://en.wikipedia.org/wiki/Message_authentication_code
        a MAC, sometimes known as a tag, is a short piece of information used for authenticating a message.
        """
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        salt = os.urandom(self.salt_size)
        self.base_key, self.hmac_key, self.iv = self._get_key_iv(
            password=key,
            salt=salt)
        print(f'IV for encryption: {self.iv}')
        print(f'base key for encryption: {self.base_key}')
        ciphertext = self._encrypt_util(
            plaintext=plaintext, initialization_vector=self.iv)
        self.hmac = new_hmac(self.hmac_key, salt +
                             ciphertext, 'sha256').digest()
        assert len(self.hmac) == self.hmac_size
        return self.hmac + salt + ciphertext

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

    def _encrypt_util(self, plaintext, initialization_vector):
        """ Utility method for encryption """
        # step 1: key expansion into 128 bit round keys / blocks
        # Initialize round keys with raw key material.
        self.round_keys = KeyScheduler().get_key_expansion_2(
            base_key=self.base_key,
            key_columns=self._convert_byte_array_to_state_matrix(
                self.base_key),
            num_rounds=self.num_rounds
        )  # self.get_key_expansion()
        print(f'Round keys = {self.round_keys}')
        # add padding; won't do anything if no padding needed
        plaintext = self._add_padding(plaintext)

        # initial round key addition; each byte of the state is combined with a byte of the round key using bitwise xor.
        encrypted_blocks = []
        prev = initialization_vector
        blocks = self._split_into_blocks(plaintext)
        print(f'Split plaintext into {len(blocks)} blocks for encryption')
        for plaintext_block in blocks:
            encrypted_block = self._encrypt_block(
                self.xor_bytes(
                    plaintext_block,
                    prev
                )
            )
            print(f'final prev = {prev}')
            encrypted_blocks.append(encrypted_block)
            prev = encrypted_block
        return b''.join(encrypted_blocks)


if __name__ == "__main__":
    # AES class parameterizes key sizes
    aes = AES(
        aes_key_size_bits=128,
        hmac_key_size_bits=128,
        hmac_size_bits=256,
        salt_size_bits=128
    )
    key = aes.generate_random_aes_key()
    message = "Hello, my name is Austin Hunt."
    ciphertext = aes.encrypt(
        key=key,
        plaintext=message
    )
    print('Encryption complete.')
    print(f'Cipher text: {ciphertext}')

    print('\n\n')

    decrypted = aes.decrypt(
        key=key,
        ciphertext=ciphertext
    )
    print(f'Decrypted: {decrypted}')
