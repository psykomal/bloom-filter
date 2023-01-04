import math
from hashlib import md5, sha256

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import urllib.parse

"""
    This is a toy implementation of Bloom Filter. 
    - SHA256 is not a good choice for Bloom filter since it is slow and has uses in cryptography areas
    - Ideal hash function should be independent, uniformly distributed and fast 
    - Examples : murmur, xxHash, the fnv series of hashes, HashMix

    The Server can be used to test the BloomFilter. 
    1. Run  `python3 bloom_filter_server.py`
    2. Add data using POST (check the method for sample request)
    2. Check data using GET (check the method for sample request)
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



class CustomHTTPServer(BaseHTTPRequestHandler):

    def error_response(self, response):
        self.send_response(400)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(response.encode())


    def do_GET(self):
        """
        Sample :
            curl --location --request GET 'localhost:8000?data=example%20data'
        """
        try:
            # Parse the query string
            query_string = self.path.split('?', 1)[1]
            query_params = {k: v for k, v in (x.split('=') for x in query_string.split('&'))}

            # Get the data value and remove %xx
            data = query_params.get('data')
            data = urllib.parse.unquote(data)
            if data:
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'value': self.server.bloom_filter.contains(data)}).encode())
            else:
                self.error_response("No data provided to check")
        except:
            self.error_response("Got unexpected request format")


    def do_POST(self):
        """
        Sample :
            curl --location --request POST 'localhost:8000' \
            --header 'Content-Type: application/json' \
            --data-raw '{
                "data": "example data"
            }'
        """
        try:
            # Parse the request body
            content_length = int(self.headers['Content-Length'])
            request_body = self.rfile.read(content_length).decode()
            request_data = json.loads(request_body)

            # Get the data value
            data = request_data.get('data')
            if data:
                self.server.bloom_filter.add(data)
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write('Data added'.encode())
            else:
                self.error_response("No data provided to add")
        except:
            self.error_response()


def run_server(server_class=HTTPServer, handler_class=CustomHTTPServer):
    # Initialize the server and bloom filter
    server = server_class(('localhost', 8000), handler_class)
    server.bloom_filter = BloomFilter(prob_fp=0.001, data_set_size=99999)

    # Start the server
    server.serve_forever()


def main():
    run_server()

if __name__=="__main__":
    main()