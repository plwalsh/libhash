
#ifndef SHA512_INTERNAL_H
#define	SHA512_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

typedef uint64_t word_t;

#define WORD_SIZE sizeof(word_t)
#define WORD_SIZE_BITS (WORD_SIZE * 8)

#define BLOCK_SIZE (WORD_SIZE * 16)
#define BLOCK_SIZE_BITS (BLOCK_SIZE * 8)

typedef struct {
	word_t length, state[8];
	unsigned long curlen;
	unsigned long buf[BLOCK_SIZE];
} sha512_state_t;

void sha512_compute(sha512_state_t * s, const uint8_t data[], const size_t size);
void sha512_conclude(sha512_state_t * s, uint8_t hash[], const size_t hash_size);

#endif
