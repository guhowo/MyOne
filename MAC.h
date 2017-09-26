#ifndef _ZT_MAC_H
#define _ZT_MAC_H

#include "Buffer.h"

typedef uint64_t MAC;

static inline MAC MAC_setTo(const void *bits,unsigned int len)
{
    MAC m;
    
    if (len < 6) {
        return 0;
    }
    const unsigned char *b = (const unsigned char *)bits;
    m =  ((((uint64_t)*b) & 0xff) << 40); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 32); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 24); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 16); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 8); ++b;
    m |= (((uint64_t)*b) & 0xff);
    return m;
}

static inline void MAC_appendTo(Buffer *buf, MAC mac)
{
    unsigned char *p=buf->b+buf->len;
    buf->len += 6;
    *(p++) = (unsigned char)((mac >> 40) & 0xff);
    *(p++) = (unsigned char)((mac >> 32) & 0xff);
    *(p++) = (unsigned char)((mac >> 24) & 0xff);
    *(p++) = (unsigned char)((mac >> 16) & 0xff);
    *(p++) = (unsigned char)((mac >> 8) & 0xff);
    *p = (unsigned char)(mac & 0xff);    
}

#endif

