# Bloom Filter

This is a toy implementation of Bloom Filter. 
- SHA256 is not a good choice for Bloom filter since it is slow and has uses in cryptography areas
- Ideal hash function should be independent, uniformly distributed and fast 
- Examples : murmur, xxHash, the fnv series of hashes, HashMix

The Server can be used to test the BloomFilter. 
1. Run  `python3 bloom_filter_server.py`
2. Add data using POST
```
    curl --location --request POST 'localhost:8000' \
            --header 'Content-Type: application/json' \
            --data-raw '{
                "data": "example data"
            }'
```
3. Check data using GET
```
    curl --location --request GET 'localhost:8000?data=example%20data'
```