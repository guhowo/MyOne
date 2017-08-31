#ifndef ZT_C25519_H
#define ZT_C25519_H

//#include "Array.hpp"
#include "Utils.h"

#define ZT_C25519_PUBLIC_KEY_LEN 64
#define ZT_C25519_PRIVATE_KEY_LEN 64
#define ZT_C25519_SIGNATURE_LEN 96

typedef unsigned char Public[ZT_C25519_PUBLIC_KEY_LEN];
/**
 * Public key (both crypto and signing)
 */
typedef unsigned char Private[ZT_C25519_PRIVATE_KEY_LEN];
/**
 * Message signature
 */
typedef unsigned char Signature[ZT_C25519_SIGNATURE_LEN];

/**
 * Public/private key pair
 */
typedef struct {
	Public pub;
	Private priv;
} Pair;

void C25519_generate(Pair *kp);
void C25519_calcPubDH(Pair *kp);
void C25519_calcPubED(Pair *kp);

/**
 * Perform C25519 ECC key agreement
 *
 * Actual key bytes are generated from one or more SHA-512 digests of
 * the raw result of key agreement.
 *
 * @param mine My private key
 * @param their Their public key
 * @param keybuf Buffer to fill
 * @param keylen Number of key bytes to generate
 */
void C25519_agree(const Private mine,const Public their,void *keybuf,unsigned int keylen);

/**
 * Sign a message with a sender's key pair
 *
 * This takes the SHA-521 of msg[] and then signs the first 32 bytes of this
 * digest, returning it and the 64-byte ed25519 signature in signature[].
 * This results in a signature that verifies both the signer's authenticity
 * and the integrity of the message.
 *
 * This is based on the original ed25519 code from NaCl and the SUPERCOP
 * cipher benchmark suite, but with the modification that it always
 * produces a signature of fixed 96-byte length based on the hash of an
 * arbitrary-length message.
 *
 * @param myPrivate My private key
 * @param myPublic My public key
 * @param msg Message to sign
 * @param len Length of message in bytes
 * @param signature Buffer to fill with signature -- MUST be 96 bytes in length
 */
void C25519_sign(const Private myPrivate,const Public myPublic,const void *msg,unsigned int len,void *signature);

/**
 * Sign a message with a sender's key pair
 *
 * @param myPrivate My private key
 * @param myPublic My public key
 * @param msg Message to sign
 * @param len Length of message in bytes
 * @return Signature
 */
static inline void C25519_sign4(Signature sig, const Private myPrivate,const Public myPublic,const void *msg,unsigned int len)
{
	C25519_sign(myPrivate,myPublic,msg,len,sig);
	return ;
}
static inline void C25519_sign3(Signature sig,const Pair *mine,const void *msg,unsigned int len)
{
	C25519_sign(mine->priv,mine->pub,msg,len,sig);
	return ;
}

/**
 * Verify a message's signature
 *
 * @param their Public key to verify against
 * @param msg Message to verify signature integrity against
 * @param len Length of message in bytes
 * @param signature 96-byte signature
 * @return True if signature is valid and the message is authentic and unmodified
 */
int C25519_verify(const Public their,const void *msg,unsigned int len,const void *signature);
static inline bool C25519_has_PrivateKey(const Private key)
{
	unsigned char k[ZT_C25519_PRIVATE_KEY_LEN];

	memset(k, 0, ZT_C25519_PRIVATE_KEY_LEN);
	if(!memcmp(key, k, ZT_C25519_PRIVATE_KEY_LEN)){
		return false;
	}
	return true;
}

#endif

