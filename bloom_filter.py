import math
from hashlib import md5, sha256


"""
    This is a toy implementation of Bloom Filter. 
    - SHA256 is not a good choice for Bloom filter since it is slow and has uses in cryptography areas
    - Ideal hash function should be independent, uniformly distributed and fast 
    - Examples : murmur, xxHash, the fnv series of hashes, HashMix
"""

def sha256_data(data: str) -> int:
    """
        Convert data string to int SHA256 hash 
        1. Computes SHA256 hash of data (data.encode converts str to byte str)
        2. hexdigest() converts byte hash to string of hexadecimal digits
        3. hexdigest -> int (base = 16)
    """
    return int(sha256(data.encode()).hexdigest(), base=16)

def md5_data(data: str) -> int:
    """
        Convert data string to int MD5 hash. Check sha256_data
    """
    return int(md5(data.encode()).hexdigest(), base=16)


class BloomFilter:
    """
        Bloom filter is a space-efficient probabilistic data structure. 
        Refer https://en.wikipedia.org/wiki/Bloom_filter
    """

    def __init__(self, prob_fp: float, data_set_size: int):
        assert(prob_fp > 0 and prob_fp <= 1)
        assert(data_set_size > 0 and data_set_size < 1e9)

        self.prob_fp = prob_fp     # Max Tolerable Probability of False Positive 
        self.data_set_size = data_set_size    # Estimated Max Set Size
        self.vector_len = self._optimal_vector_len(self.prob_fp, self.data_set_size)   # Length of bitarray optimized for prob_fp and data_set_size params
        self.num_hashes = self._optimal_num_hashes(self.prob_fp)  # Optimal Num hash functions based on given prob_fp and data_set_size params 

        self.bitvec = [0 for _ in range(self.vector_len)]    # ideally to use BitVector here (libs like bitarray)

    def add(self, data):
        """
            Allows addition of data in str format
        """
        for n in range(self.num_hashes):
            hash_val = self._generate_hash_func(n)(data) % self.vector_len
            self.bitvec[hash_val] = 1

    def contains(self, data) -> bool:
        """
            Checks whether data is present or not
                - if False, data is not present with 100% probability
                - if True, data might or might not be present (Can be a false postiive)
        """
        for n in range(self.num_hashes):
            hash_val = self._generate_hash_func(n)(data) % self.vector_len
            if not self.bitvec[hash_val]:
                return False
        return True

    def _generate_hash_func(self, iter_n: int) -> callable:
        """
            Generate new hash function based on param iter_n
        """
        return lambda data: md5_data(data) + iter_n * sha256_data(data)

    def _optimal_num_hashes(self, prob_fp: float) -> int:
        ln2 = math.log(2)
        return math.ceil(-math.log(prob_fp)/ln2)

    def _optimal_vector_len(self, prob_fp: float, data_set_size: int) -> int:
        ln2 = math.log(2)
        return math.ceil(-((data_set_size * math.log(prob_fp))/(ln2**2)))

        


    