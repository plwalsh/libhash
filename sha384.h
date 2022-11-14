
#ifndef SHA384_H
#define	SHA384_H

#include <stddef.h>
#include <stdint.h>

#include "sha512_internal.h"

#define SHA384_HASH_SIZE 48
#define SHA384_STRING_HASH_SIZE ((SHA384_HASH_SIZE * 2) + 1)

typedef sha512_state_t sha384_state_t;

void sha384_init(sha384_state_t * state);
void sha384_process(sha384_state_t * state, const void * const data, const size_t size);
void sha384_done(sha384_state_t * state, uint8_t hash[SHA384_HASH_SIZE]);

void sha384_simple(const void * const data, const size_t size, uint8_t hash[SHA384_HASH_SIZE]);

void sha384_hash_to_string(const uint8_t hash[SHA384_HASH_SIZE], char dest[SHA384_STRING_HASH_SIZE]);

#endif
