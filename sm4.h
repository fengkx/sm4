#ifndef _sm4_H_
#define _sm4_H_

#include <stdint.h>

#define SM4_DECRYPT 0
#define SM4_ENCRYPT 1

#define SM4_BLOCK_SIZE    16
#define SM4_KEY_SCHEDULE  32

typedef struct {
	int mode; // ENCRYPT OR DECRYPT
	uint32_t rk[SM4_KEY_SCHEDULE]; // rotkey

}
sm4_ctx;

	int sm4_set_key(const uint8_t *key, sm4_ctx * const ctx); // key 128 bit len 16 
	void sm4_encrypt(const uint8_t *in, uint8_t *out, const sm4_ctx *ctx);
	void sm4_decrypt(const uint8_t *in, uint8_t *out, const sm4_ctx *ctx);

	static inline uint32_t load_uint32_be(const uint8_t *b, int n);
	static inline void store_uint32_be(uint32_t v, uint8_t * const b);
	static inline void SM4_F(uint32_t * const blks, const uint32_t *rkg); // blks len should be 4 as 128bit
	static inline uint32_t SM4_T(uint32_t X);

#endif // _sm4_H_
