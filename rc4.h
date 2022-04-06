#ifndef RC4_H
#define RC4_H

#include <stddef.h>
#include <stdint.h>

#define RC4_STATE_SIZE 256

struct rc4_ctx {
	uint8_t pos1;
	uint8_t pos2;
	uint8_t state[RC4_STATE_SIZE];
};

// Initialize RC4 context
void rc4_init(struct rc4_ctx *ctx, const uint8_t *key, size_t len);

// Skip stream bytes
void rc4_skip(struct rc4_ctx *ctx, size_t len);

// Generate RC4 key stream bytes
void rc4_stream(struct rc4_ctx *ctx, void *buffer, size_t len);

// Encrypt or decrypt a buffer
void rc4_crypt(struct rc4_ctx *ctx, void *buffer, size_t len);
#endif
