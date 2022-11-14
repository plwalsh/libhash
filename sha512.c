
#include <stdio.h>
#include <string.h>

#include "sha512.h"

void sha512_init(sha512_state_t * s) {
    s->curlen = 0;
    s->length = 0;
    s->state[0] = 0x6a09e667f3bcc908;
    s->state[1] = 0xbb67ae8584caa73b;
    s->state[2] = 0x3c6ef372fe94f82b;
    s->state[3] = 0xa54ff53a5f1d36f1;
    s->state[4] = 0x510e527fade682d1;
    s->state[5] = 0x9b05688c2b3e6c1f;
    s->state[6] = 0x1f83d9abfb41bd6b;
    s->state[7] = 0x5be0cd19137e2179;
}

void sha512_process(sha512_state_t * s, const void * const data, const size_t size) {
    sha512_compute(s, data, size);
}

void sha512_done(sha512_state_t * s, uint8_t hash[SHA512_HASH_SIZE]) {
    sha512_conclude(s, hash, SHA512_HASH_SIZE);
}

void sha512_simple(const void * const data, const size_t size, uint8_t hash[SHA512_HASH_SIZE]) {
    sha512_state_t s;
    sha512_init(&s);
    sha512_process(&s, data, size);
    sha512_done(&s, hash);
}

void sha512_hash_to_string(const uint8_t hash[SHA512_HASH_SIZE], char dest[SHA512_STRING_HASH_SIZE]) {
    int i;
    for (i = 0; i < SHA512_HASH_SIZE; i++) {
        sprintf(dest + i * 2, "%.2x", hash[i]);
    }
}
