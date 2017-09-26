#ifndef _ZT_BUFFER_H
#define _ZT_BUFFER_H

#include "Utils.h"

#if defined(__GNUC__) && (!defined(ZT_NO_TYPE_PUNNING))
#define ZT_VAR_MAY_ALIAS __attribute__((__may_alias__))
#else
#define ZT_VAR_MAY_ALIAS
#endif

typedef struct buffer{
    unsigned int len;
    unsigned char b[1024*50];
}Buffer;

static inline void append(Buffer *buf, const unsigned char v)
{
    unsigned char *const p = buf->b + buf->len;
    *p = v;
    buf->len +=  sizeof(v);
}

static inline void append_uint32(Buffer *buf, uint32_t v)
{
#ifdef ZT_NO_TYPE_PUNNING
        uint8_t *p = (uint8_t *)(buf->b[buf->len]);
        for(unsigned int x=1;x<=sizeof(uint32_t);++x)
            *(p++) = (uint8_t)(v >> (8 * (sizeof(uint32_t) - x)));
#else
        uint32_t *const ZT_VAR_MAY_ALIAS p = (uint32_t*)(buf->b + buf->len);
        *p = htonl(v);
#endif
        buf->len += sizeof(uint32_t);
}

static inline void append_uint64(Buffer *buf, uint64_t v)
{
#ifdef ZT_NO_TYPE_PUNNING
        uint8_t *p = (uint8_t *)(buf->b[buf->len]);
        for(unsigned int x=1;x<=sizeof(uint64_t);++x)
            *(p++) = (uint8_t)(v >> (8 * (sizeof(uint64_t) - x)));
#else
        uint64_t *const ZT_VAR_MAY_ALIAS p = (uint64_t*)(buf->b + buf->len);
        *p = Utils_hton_u64(v);
#endif
        buf->len += sizeof(uint64_t);
}

static inline void append_uint16(Buffer *buf, uint16_t v)
{
#ifdef ZT_NO_TYPE_PUNNING
        uint8_t *p = (uint8_t *)(buf->b[buf->len]);
        for(unsigned int x=1;x<=sizeof(uint16_t);++x)
            *(p++) = (uint8_t)(v >> (8 * (sizeof(uint16_t) - x)));
#else
        uint16_t *const ZT_VAR_MAY_ALIAS p = (uint16_t*)(buf->b + buf->len);
        *p = htons(v);
#endif
        buf->len += sizeof(uint16_t);
}



static inline void append_databylen(Buffer *buf, const void *data,unsigned int l)
{
    memcpy((buf->b+buf->len), data, l);
    buf->len += l;
}


static inline void setAt(Buffer *buf, unsigned int i,const uint16_t v)
{
    uint16_t *const ZT_VAR_MAY_ALIAS p = (uint16_t *)(buf->b + i);
    *p = htons(v);
}

static inline uint16_t at_u16(Buffer *buf, unsigned int i)
{
    const uint16_t *const ZT_VAR_MAY_ALIAS p =(const uint16_t *)(buf->b + i);
    return ntohs(*p);
}

static inline uint16_t at_u32(Buffer *buf, unsigned int i)
{
    const uint32_t *const ZT_VAR_MAY_ALIAS p =(const uint32_t *)(buf->b + i);
    return ntohl(*p);
}

static inline uint64_t at_u64(Buffer *buf, unsigned int i)
{
    const uint64_t *const ZT_VAR_MAY_ALIAS p =(const uint64_t *)(buf->b + i);
    return Utils_ntoh_u64(*p);
}

static inline void Buffer_Init(Buffer * b){
    b->len = 0;
}

#endif 
