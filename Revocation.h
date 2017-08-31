#ifndef _REVOCATION_H
#define _REVOCATION_H

#include "Constants.h"
#include "ZeroTierOne.h"
#include "Address.h"
#include "C25519.h"
#include "Utils.h"
#include "Buffer.h"
#include "Identity.h"

typedef struct {
	uint32_t _id;
	uint32_t _credentialId;
	uint64_t _networkId;
	uint64_t _threshold;
	uint64_t _flags;
	Address _target;
	Address _signedBy;
	enum Credential _type;
	Signature _signature;
}Revocation;

void Revocation_serialize(Buffer *buf,const bool forSign, Revocation *rev);
unsigned int Revocation_deserialize(Buffer *buf,unsigned int startAt, Revocation *rev);

#endif
