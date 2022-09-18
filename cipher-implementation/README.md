# Write or Implement a Cipher

Your cipher should both encrypt and decrypt a message. Your cipher may be one of your own construction or a common one of any strength you find on the Internet (from Caesar or Vigenere to FIP 140-2 ciphers such as AES).

You must include your code and sample runs including screenshots. If you implement a known cipher, it will have test inputs for verification and those should be used.

## Chosen cipher: AES

I'm choosing to implement the AES algorithm mainly because it's daunting and I'm bound to learn quite a bit from it.

I'm taking some notes on how the AES (Advanced Encryption Standard) cipher algorithm works below, using [this video](https://www.youtube.com/watch?v=O4xNJsjtN6E) as a reference. (and many others)

- 128 bit symmetric block cipher
- key can be 128, 192, or 256 bits.
- message broken into 128 bit blocks, potentially padded if not broken evenly
- initialization vector used for randomization & **semantic security**, a property whereby repeated usage of the scheme under the same key does not allow an attacker to infer relationships between (potentially similar) segments of the encrypted message.
- State in algorithm represented with a 4x4 grid, byte0 through 3 in first column, 4 through 7 in second column, etc. Everything happens using that grid.
- Encryption happens one 128-bit block at a time.
- Broken into N rounds, N = 10 for 128-bit key, N=12 for 192-bit key, N=14 for 256-bit key.
- You have to generate N+1 round keys (a key for each round plus one)
  - 11 for 128-bit key, 13 for 192-bit key, 15 for 256-bit key
    ![key expansion, or key scheduling](img/keyschedule.png)
- AES is now built into hardware; inherently on Intel chips, AMD chips;

1. Start with plaintext
2. Expand key into different round keys using a **key schedule**. Will probably write a Python class to handle this alone.
   1. Explained quite well here: [https://www.youtube.com/watch?v=rmqWaktEpcw](https://www.youtube.com/watch?v=rmqWaktEpcw)
3. Use part of key ($k_0$) for XOR operation
4. Then do round:
   1. Substitute bytes
      1. Each byte mapped to a different byte in a lookup table within finite field. This mapping is very non-linear, so it's hard to represent mathematically.
      2. There are no fixed points, so no byte is substituted with itself (as you'd see in the random substitution cipher).
      3. There are no _opposite_ fixed points, meaning there are no substitutions that simply flip each bit.
      4. Within 4x4 grid, each cell is a byte; replace each cell with substituted byte.
         1. ![byte substitution](img/byte-sub.png)
   2. Shift rows
      1. Don't shift first row. Shift second row one to the left; shift third row two to the left; shift fourth row 3 to the left.
         1. ![row shift](img/row-shift.png)
   3. Mix columns
      1. Similar to above, but column-wise mixing for each column. Mixing is done with matrix multiplication. There's a reverse inverse matrix that does the exact opposite when you want to decrypt as well.
      2. Don't mix columns in final round because it doesn't do anything useful.
      3. Referenced Design of Rijndael section 4.1.2
         1. ![design of rijndael section 4.1.2](img/design-of-rijndael.png)
      4. Also referenced Design of Rijndael section 4.1.3 for decryption/inverse mix columns
         1. ![design of rijndael section 4.1.3](img/rijndael-inverse-mix-columns-4.1.3.png)
   4. Add round key
      ![AES round](img/aes-round.png)

AES in a nutshell is built on repeated rounds of "SP" - substitution and permutation. The substitution is defined by an "S-box", basically the map of bytes with their respective substitute bytes. AES happens to be built on the Rijndael S-box, seen here:
![rijndael substitution box](img/rijndaelsbox.png)
Then, for decryption, there is the inverse S-box:
![inverse substitution box](img/rijndaelinversesbox.png)

[main.py](main.py) leverages the S box and inverse S box heavily for byte substitution.
