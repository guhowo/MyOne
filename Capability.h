#ifndef _CAPABILITY_H
#define _CAPABILITY_H

#include "Constants.h"
#include "Address.h"
#include "C25519.h"
#include "Utils.h"
#include "Buffer.h"
#include "Identity.h"
#include "ZeroTierOne.h"


typedef struct _Capability{
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
void Capability_serializeRules(Buffer *buf,const ZT_VirtualNetworkRule *rules, unsigned int ruleCount);
unsigned int Capability_deserialize(Buffer *buf,unsigned int startAt, Capability *cb);
void Capability_deserializeRules(Buffer *buf, unsigned int *k, ZT_VirtualNetworkRule *rules, unsigned int *rc,const unsigned int maxRuleCount);
static inline int Capability_compare(const void *a,const void *b)
{
    return (((Capability *)a)->id < ((Capability *)b)->id);    
}

#endif
