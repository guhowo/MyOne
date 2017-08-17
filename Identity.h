#ifndef ZT_IDENTITY_H
#define ZT_IDENTITY_H

#include "Buffer.h"
#include "Address.h"


/**
 * A ZeroTier identity
 *
 * An identity consists of a public key, a 40-bit ZeroTier address computed
 * from that key in a collision-resistant fashion, and a self-signature.
 *
 * The address derivation algorithm makes it computationally very expensive to
 * search for a different public key that duplicates an existing address. (See
 * code for deriveAddress() for this algorithm.)
 */
typedef struct _identity{
	Address _address;
	unsigned char _publicKey[64];		//C25519::Public
	unsigned char _privateKey[64];		//C25519::Private
}Identity;



/**
 * Generate a new identity (address, key pair)
 *
 * This is a time consuming operation.
 */
Identity identity_generate(void);

void identity_serialize(Identity *identity, Buffer *buf, bool includePrivate);
int identity_deserialize(Identity *id, const unsigned char *b, unsigned int startAt);
bool Identity_fromString(const char *str, Identity *id);
bool agree(const Identity *id,void *key,unsigned int klen);
bool locallyValidate(Identity *id);

/**
 * return true : two identities are the same
 * return false: two identities are different
 */
static inline bool idIsEqual(Identity *ida, Identity *idb)
{
	return ((ida->_address._a == idb->_address._a)&&(memcmp(ida->_publicKey, idb->_publicKey, 64)==0));
}

#endif

