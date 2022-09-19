from functools import reduce
from rijndael import Rijndael


class Util(Rijndael):

    def xor_bytes(self, a, b):
        """ Returns a new byte array with the elements xor'ed. """
        return bytes(i ^ j for i, j in zip(a, b))

    ## Padding ##
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
    ## Padding ##

    ## Data transformations ##
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
        print(f'Matrix: {matrix}')
        return matrix

    def _convert_state_matrix_to_byte_array(self, matrix: list):
        """ Convert a 4x4 state matrix back into a byte array  """
        flattened = sum(matrix, [])  # easy way to flatten 2d array
        flattened_bytes = bytes(flattened)
        return flattened_bytes

    ## Data transformations ##

    ## Rijndael ##
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

    ## Rijndael ##

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
