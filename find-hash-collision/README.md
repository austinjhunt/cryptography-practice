# Finding Partial Hash Collisions

The goal of this script is to simply find partial hash collisions (of the first 5 hash characters) between messages, where messages can be either numbers or strings.

I used multithreading in Python to quickly find partial collisions of the first 5 hash characters between both

a) integers ranging from 0 to 1 million
b) random strings of lengths between 1 and 1000

I used the concurrent.futures.ThreadPoolExecutor library and broke these large intervals up into chunks of 10,000 and 25 respectively (10,000 chunks for integers, and 25 chunks for random strings of length N).
Each chunk is assigned to its own thread.

## Running it

```
cd find-hash-collision
python main.py
```

It will produce `hashes.json` and `partial-collisions.txt`. The partial collisions text file is ultimately a subset of the hashes JSON file but it only includes those hashes whose corresponding lists of inputs have more than one item, since more than one indicates a collision.
