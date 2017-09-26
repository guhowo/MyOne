#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Address.h"

void Address_SetTo(const void *bits,unsigned int len, Address *addr)
{
    if (len < ZT_ADDRESS_LENGTH) {
        memset(addr, 0, sizeof(Address));
        return;
    }
    const unsigned char *b = (const unsigned char *)bits;
    *addr = ((uint64_t)*b++) << 32;
    *addr |= ((uint64_t)*b++) << 24;
    *addr |= ((uint64_t)*b++) << 16;
    *addr |= ((uint64_t)*b++) << 8;
    *addr |= ((uint64_t)*b);
}

void Address_CopyTo(void *bits,unsigned int len, Address addr)
{
    if (len < ZT_ADDRESS_LENGTH)
        return;
    unsigned char *b = (unsigned char *)bits;
    *(b++) = (unsigned char)((addr >> 32) & 0xff);
    *(b++) = (unsigned char)((addr >> 24) & 0xff);
    *(b++) = (unsigned char)((addr >> 16) & 0xff);
    *(b++) = (unsigned char)((addr >> 8) & 0xff);
    *b = (unsigned char)(addr & 0xff);
}

void Address_AppendTo(Buffer *buf, Address addr)
{    
    unsigned char *p = (unsigned char *)(buf->b + buf->len);
    buf->len += ZT_ADDRESS_LENGTH;
    *(p++) = (unsigned char)((addr >> 32) & 0xff);
    *(p++) = (unsigned char)((addr >> 24) & 0xff);
    *(p++) = (unsigned char)((addr >> 16) & 0xff);
    *(p++) = (unsigned char)((addr >> 8) & 0xff);
    *p = (unsigned char)(addr & 0xff);
}

char *Address_ToString(Address addr)
{
    char *buf = (char *)malloc(16);
    snprintf(buf,16,"%.10llx",(unsigned long long )addr);
    return buf;
}

bool Address_IsReserved(Address a)
{
    return ((!a)||((a >> 32) == ZT_ADDRESS_RESERVED_PREFIX));
}






