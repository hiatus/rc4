#include "rc4.h"

void rc4_init(struct rc4_ctx *ctx, const uint8_t *key, size_t len)
{
	uint8_t aux;

	ctx->pos1 = ctx->pos2 = 0;

	for (uint_fast16_t i = 0; i < RC4_STATE_SIZE; ++i)
		ctx->state[i] = i;

	for (uint_fast16_t j = 0, i = 0; i < RC4_STATE_SIZE; ++i) {
		j = (j + i + key[i % len]) % RC4_STATE_SIZE;

		aux = ctx->state[i];
		ctx->state[i] = ctx->state[j];
		ctx->state[j] = aux;
	}
}

void rc4_skip(struct rc4_ctx *ctx, size_t len)
{
	uint8_t aux;

	for (size_t i = 0; i < len; ++i) {
		ctx->pos1 = (ctx->pos1 + 1) % RC4_STATE_SIZE;
		ctx->pos2 = (ctx->pos2 + ctx->state[ctx->pos1]) % RC4_STATE_SIZE;

		aux = ctx->state[ctx->pos1];
		ctx->state[ctx->pos1] = ctx->state[ctx->pos2];
		ctx->state[ctx->pos2] = aux;
	}
}


void rc4_stream(struct rc4_ctx *ctx, void *buffer, size_t len)
{
	uint8_t aux;

	for (size_t i = 0; i < len; ++i) {
		ctx->pos1 = (ctx->pos1 + 1) % RC4_STATE_SIZE;
		ctx->pos2 = (ctx->pos2 + ctx->state[ctx->pos1]) % RC4_STATE_SIZE;

		aux = ctx->state[ctx->pos1];
		ctx->state[ctx->pos1] = ctx->state[ctx->pos2];
		ctx->state[ctx->pos2] = aux;

		*((uint8_t *)buffer + i) = ctx->state[
			(ctx->state[ctx->pos1] + ctx->state[ctx->pos2]) % RC4_STATE_SIZE
		];
	}
}

void rc4_crypt(struct rc4_ctx *ctx, void *buffer, size_t len)
{
	uint8_t aux;

	for (size_t i = 0; i < len; ++i) {
		ctx->pos1 = (ctx->pos1 + 1) % RC4_STATE_SIZE;
		ctx->pos2 = (ctx->pos2 + ctx->state[ctx->pos1]) % RC4_STATE_SIZE;

		aux = ctx->state[ctx->pos1];
		ctx->state[ctx->pos1] = ctx->state[ctx->pos2];
		ctx->state[ctx->pos2] = aux;

		*((uint8_t *)buffer + i) ^= ctx->state[
			(ctx->state[ctx->pos1] + ctx->state[ctx->pos2]) % RC4_STATE_SIZE
		];
	}
}
