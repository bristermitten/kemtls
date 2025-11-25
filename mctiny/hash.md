The `hash` library returns a 32-byte cryptographic hash of its input.
Currently the hash function is SHAKE-256.
Usage:

       #include "hash.h"

       unsigned char in[...];
       unsigned char out[32];

       hash(out,in,sizeof in);
