"""
Script for decrypting the contents of enc.txt encrypted with a substitution cipher.

The contents of enc.txt is a famous text that has been encoded using a substitution cipher.
As we've learned in class, a frequency analysis can be done of these types of texts to ascertain the key
- or something very near the key.

Tutorial on using / cracking substitution ciphers: https://www.youtube.com/watch?v=LhS8N6oJdno
(both caesar shifts and random substitutions)

"""
from string import ascii_lowercase
import json
import os
ENCRYPTED_FILE = os.path.join(os.path.dirname(__file__), 'enc.txt')
DECRYPTED_FILE = os.path.join(os.path.dirname(__file__), 'dec.txt')
KEY_FILE = os.path.join(os.path.dirname(__file__), 'key.json')
DIRNAME = os.path.dirname(__file__)


def decrypt_content_with_key(key):
    """ given a key (a map between characters of the alphabet representing
    substitutions to make) decrypt text encrypted with substitution cipher;
    replace with capital letter to avoid overwriting a replacement since
    source is purely lowercase """
    with open(ENCRYPTED_FILE) as f:
        content = f.read()
    decrypted = content
    for enc, dec in key.items():
        # to avoid overwriting on future iteration if dec is a key in the key dict.
        decrypted = decrypted.replace(enc, dec.upper())
    with open(DECRYPTED_FILE, 'w') as f:
        f.write(decrypted)


def get_character_frequencies():
    """ Return a dictionary of the counts of each character in the encrypted content """
    print('Getting character frequencies')
    with open(ENCRYPTED_FILE) as f:
        content = f.read()
    freqs = {}
    for char in content:
        if char in freqs:
            freqs[char] += 1
        else:
            freqs[char] = 1
    # sort by value/counts (descending)
    freqs = {k: v for k, v in sorted(
        freqs.items(), key=lambda item: item[1], reverse=True)}
    with open(f'{DIRNAME}/char-freqs.json', 'w') as f:
        json.dump(freqs, f)


def get_word_freqencies():
    print(f'Getting word frequencies')
    with open(ENCRYPTED_FILE) as f:
        content = f.read()
    _split = content.split()
    for i in range(1, 7):
        print(f'Getting word (length={i}) frequencies')
        words_of_this_length = [el for el in _split if len(el) == i]
        # now get frequencies of words of this length
        freqs = {}
        for w in words_of_this_length:
            if w in freqs:
                freqs[w] += 1
            else:
                freqs[w] = 1
        # sort by value/counts (descending)
        freqs = {k: v for k, v in sorted(
            freqs.items(), key=lambda item: item[1], reverse=True)}
        with open(f'{DIRNAME}/words-of-length-{i}-freqs.json', 'w') as f:
            json.dump(freqs, f)


get_character_frequencies()
get_word_freqencies()

# What I know at this point:
# q is most common single-letter word. h is next most common single letter word.
# replace q with a and replace h with i.

key = {
    'q': 'a',
    'h': 'i',
}
# also know that qbd is second most common 3 letter word behind esz. qbd is likely "and",
key['b'] = 'n'
key['d'] = 'd'

# esz is very likely "the"
key['e'] = 't'
key['s'] = 'h'
key['z'] = 'e'

# extrapolating from there; common words beginning with the with other letters include:
# then
# them
# they
# their

# eszpz is second most common 5 letter word.
# eszhp is 4th most common.
# z repeats in eszpz. Definitely "there". So second one must be "their":
key['p'] = 'r'
key['h'] = 'i'

# eshw is very common; given above, that's "this"
key['w'] = 's'

# also know esqe is most common 4 letter word. given above, that's "that". makes sense.
# also, ches is second most common 4 letter word.
# key['c'] = ''

# ai is most common 2 letter word. considered "is" but s already used, so try "it".
key['a'] = 'i'
key['i'] = 't'


decrypt_content_with_key(key)

# found phrase kHARfES DIkoENS after the above.
key['k'] = 'c'
key['o'] = 'k'
key['f'] = 'l'

decrypt_content_with_key(key)

# now have: THE nRIyECT tjTENgERt EgIIK IT A TALE IT TcI CITIES, gr CHARLES DICKENS
# replace keys a and i ; don't want IT, want OF
key['a'] = 'o'
key['i'] = 'f'
# also, c must be w
key['c'] = 'w'

# gr should be "by" - "by Charles Dickens"
key['g'] = 'b'
key['r'] = 'y'

decrypt_content_with_key(key)

# THE nROyECT tjTENBERt EBOOK OF A TALE OF TWO CITIES, BY CHARLES DICKENS
# should be
# THE PROJECT GUTENBERG EBOOK OF A TALE OF TWO CITIES, BY CHARLES DICKENS
key['n'] = 'p'
key['y'] = 'j'
key['t'] = 'g'
key['j'] = 'u'

decrypt_content_with_key(key)

# remaining is a bit obvious.
key['v'] = 'v'
key['u'] = 'm'

decrypt_content_with_key(key)


def get_remaining_characters_not_in_key(key):
    # identify remaining characters to finish map
    return [l for l in ascii_lowercase if l not in key.keys()]


remaining = get_remaining_characters_not_in_key(key)
# remaining: l, m, x
key['m'] = 'q'  # mUEEN repeated
key['x'] = 'x'  # SIx, VExED, BOx, used in roman numerals
key['l'] = 'z'  # THAT’S A BLAlING STRANGE ANSWER, TOO; DOlEN


# should not be any remaining characters not in key
assert not get_remaining_characters_not_in_key(key)

print(f'Creating key.json file')
sorted_key = dict(sorted(key.items()))
decrypt_content_with_key(sorted_key)
with open(KEY_FILE, 'w') as f:
    json.dump(sorted_key, f)
