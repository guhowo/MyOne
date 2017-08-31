#ifndef _CAPABILITY_H
#define _CAPABILITY_H

#include "Constants.h"
#include "Address.h"
#include "C25519.h"
#include "Utils.h"
#include "Buffer.h"
#include "Identity.h"
#include "ZeroTierOne.h"


typedef struct {
	uint64_t nwid;
	uint64_t ts;
	uint32_t id;
	unsigned int maxCustodyChainLength;	
	unsigned int ruleCount;
	ZT_VirtualNetworkRule rules[ZT_MAX_CAPABILITY_RULES];
	struct {
		Address to;
		Address from;
		Signature signature;
	} custody[ZT_MAX_CAPABILITY_CUSTODY_CHAIN_LENGTH];
}Capability;

void Capability_serialize(Buffer *buf,const bool forSign, Capability *cb);
unsigned int Capability_deserialize(Buffer *buf,unsigned int startAt, Capability *cb);
static inline int Capability_compare(const Capability *a,const Capability *b)
{
	return (a->id < b->id);	
}

#endif
