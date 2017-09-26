#ifndef _TAG_H
#define _TAG_H

#include "Constants.h"
#include "C25519.h"
#include "Address.h"
#include "Identity.h"
#include "Buffer.h"

typedef struct{
    uint32_t id;
    uint32_t value;
    uint64_t networkId;
    uint64_t ts;
    Address issuedTo;
    Address signedBy;
    Signature signature;
}Tag;

void Tag_serialize(Buffer *buf,const bool forSign, Tag *tag);
unsigned int Tag_deserialize(Buffer *buf,unsigned int startAt, Tag *tag);
static inline int Tag_compare(const void *a,const void *b)
{
    return (((Tag *)a)->id < ((Tag *)b)->id);
}

#endif
