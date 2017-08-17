#ifndef ZT_POLY1305_H
#define ZT_POLY1305_H

#define ZT_POLY1305_KEY_LEN 32
#define ZT_POLY1305_MAC_LEN 16

/**
 * Poly1305 one-time authentication code
 *
 * This takes a one-time-use 32-byte key and generates a 16-byte message
 * authentication code. The key must never be re-used for a different
 * message.
 *
 * In Packet this is done by using the first 32 bytes of the stream cipher
 * keystream as a one-time-use key. These 32 bytes are then discarded and
 * the packet is encrypted with the next N bytes.
 */
void Poly1305_compute(void *auth,const void *data,unsigned int len,const void *key);

#endif

