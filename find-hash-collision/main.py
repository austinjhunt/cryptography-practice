"""Austin Hunt
14 Sept 2022

Find two messages (strings or numbers) whose hexdigest collides in the first five characters.

Example provided:
sha256(bytes(1000).hexdigest())[:4] == sha256(bytes(344962).hexdigest())[:4]
"""
from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor, wait
import time
import json
import os
from string import ascii_letters
import random

PYTHONHASHSEED = 175


class CollisionFinder:
    def __init__(self):
        self.hashes = {}

    def calculate_number_hashes(self, start, end_inclusive):
        print(
            f'Starting hash calculations for range {start} to {end_inclusive}')
        for i in range(start, end_inclusive + 1):
            hash_first_five = sha256(bytes(i)).hexdigest()[:5]
            if hash_first_five in self.hashes:
                self.hashes[hash_first_five].append(i)
            # think there's an issue here producing inconsistent results with multithreading.
            # if thread 1 gets to else; thread 2 takes over and sets self.hashes[hash_first_five] to [12345] then thread 1 overwrites.
            # non-deterministic results. e.g. 95 collisions total for execution 1, 105 for another, 88 for another.
            # not too important for this assignment but worth investigating.
            else:
                self.hashes[hash_first_five] = [i]

    def work_numbers(self):
        futures = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            for i in range(0, 1000000, 10000):
                if i == 0:
                    start = 0
                else:
                    start = i + 1
                end = i + 100
                futures.append(
                    executor.submit(self.calculate_number_hashes, start, end)
                )
        for f in wait(futures).done:
            pass

    def generate_random_string_of_length_n(self, n):
        return ''.join(random.choices(ascii_letters, k=n))

    def calculate_string_hashes(self, start, end_inclusive):
        NUM_RANDOM_STRINGS = 5
        print(
            f'Starting string hash calculations for random strings between lengths {start} and {end_inclusive}')
        for i in range(start, end_inclusive + 1):
            for j in range(NUM_RANDOM_STRINGS):
                rand_string = self.generate_random_string_of_length_n(i)
                hash_first_five = sha256(
                    bytes(rand_string.encode('utf-8'))).hexdigest()[:5]
                if hash_first_five in self.hashes:
                    self.hashes[hash_first_five].append(rand_string)
                else:
                    self.hashes[hash_first_five] = [rand_string]

    def work_strings(self):
        futures = []
        with ThreadPoolExecutor(max_workers=50) as executor:
            for rand_message_length in range(1, 1000, 25):
                start = rand_message_length + 1
                end = rand_message_length + 25
                futures.append(
                    executor.submit(self.calculate_string_hashes, start, end)
                )
            for f in wait(futures).done:
                pass

    def save_hashes(self):
        print('Saving hashes')
        with open('hashes.json', 'w') as f:
            json.dump(self.hashes, f)

    def get_partial_collisions(self):
        return [(hash_collided, src) for hash_collided, src in self.hashes.items() if len(src) > 1]


if __name__ == "__main__":
    finder = CollisionFinder()
    start = time.time()
    finder.work_numbers()
    end = time.time()
    print(f'Elapsed time for numeric hash calculations: {end - start} seconds')
    start = time.time()
    finder.work_strings()
    end = time.time()
    print(f'Elapsed time for string hash calculations: {end - start} seconds')

    print('Saving hashes')
    finder.save_hashes()

    print('Collecting all partial collisions from saved hashes')
    partial_collisions = finder.get_partial_collisions()
    print(f'Found {len(partial_collisions)} partial collisions')
    fpath = os.path.join(os.path.dirname(__file__), 'partial-collisions.txt')
    with open(fpath, 'w') as f:
        for pc in partial_collisions:
            f.write(
                f'These {len(pc[1])} numbers/strings when hashed produce a partial collision '
                f'(shared first 5 hash value characters of '
                f'{pc[0]}): {", ".join([str(el) for el in pc[1]])} \n')
