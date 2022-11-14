
#include <stdio.h>
#include <string.h>

#include "sha384.h"

void sha384_init(sha384_state_t * s) {
    s->curlen = 0;
    s->length = 0;
    s->state[0] = 0xcbbb9d5dc1059ed8;
    s->state[1] = 0x629a292a367cd507;
    s->state[2] = 0x9159015a3070dd17;
    s->state[3] = 0x152fecd8f70e5939;
    s->state[4] = 0x67332667ffc00b31;
    s->state[5] = 0x8eb44a8768581511;
    s->state[6] = 0xdb0c2e0d64f98fa7;
    s->state[7] = 0x47b5481dbefa4fa4;
}

void sha384_process(sha384_state_t * s, const void * const data, const size_t size) {
    sha512_compute(s, data, size);
}

void sha384_done(sha384_state_t * s, uint8_t hash[SHA384_HASH_SIZE]) {
    sha512_conclude(s, hash, SHA384_HASH_SIZE);
}

void sha384_simple(const void * const data, const size_t size, uint8_t hash[SHA384_HASH_SIZE]) {
    sha384_state_t s;
    sha384_init(&s);
    sha384_process(&s, data, size);
    sha384_done(&s, hash);
}

void sha384_hash_to_string(const uint8_t hash[SHA384_HASH_SIZE], char dest[SHA384_STRING_HASH_SIZE]) {
    int i;
    for (i = 0; i < SHA384_HASH_SIZE; i++) {
        sprintf(dest + i * 2, "%.2x", hash[i]);
    }
}
