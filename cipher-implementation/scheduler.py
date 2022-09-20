from rijndael import Rijndael
from util import Util


class KeyScheduler(Util):
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
        # print(
        #    f'inverse substitution 32 bit word for 32 word input {word} is {sub}')
        return sub

    def get_key_expansion(self, base_key, key_columns, num_rounds):
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
