
#ifndef SHA512_H
#define	SHA512_H

#include <stddef.h>
#include <stdint.h>

#include "sha512_internal.h"

#define SHA512_HASH_SIZE 64
#define SHA512_STRING_HASH_SIZE ((SHA512_HASH_SIZE * 2) + 1)

void sha512_init(sha512_state_t * s);
void sha512_process(sha512_state_t * s, const void * const data, const size_t size);
void sha512_done(sha512_state_t * s, uint8_t hash[SHA512_HASH_SIZE]);

void sha512_simple(const void * const data, const size_t size, uint8_t hash[SHA512_HASH_SIZE]);

void sha512_hash_to_string(const uint8_t hash[SHA512_HASH_SIZE], char dest[SHA512_STRING_HASH_SIZE]);

#endif
