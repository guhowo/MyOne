#ifndef ZT_SHA512_H
#define ZT_SHA512_H

#define ZT_SHA512_DIGEST_LEN 64

/**
 * SHA-512 digest algorithm
 */
void SHA512_hash(void *digest,const void *data,unsigned int len);
#endif

