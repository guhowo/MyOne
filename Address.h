#ifndef ZT_ADDRESS_H
#define ZT_ADDRESS_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "Constants.h"
#include "Utils.h"
#include "Buffer.h"



/**
 * A ZeroTier address
 */
typedef struct _Address {
	uint64_t _a;
}Address;


/**
* @param bits Raw address -- 5 bytes, big-endian byte order
* @param len Length of array
*/
static inline void address_setTo(const void *bits,unsigned int len, Address *addr)
{
	if (len < ZT_ADDRESS_LENGTH) {
		memset(addr, 0, sizeof(Address));
		return;
	}
	const unsigned char *b = (const unsigned char *)bits;
	addr->_a = ((uint64_t)*b++) << 32;
	addr->_a |= ((uint64_t)*b++) << 24;
	addr->_a |= ((uint64_t)*b++) << 16;
	addr->_a |= ((uint64_t)*b++) << 8;
	addr->_a |= ((uint64_t)*b);
}


/**
 * @param bits Buffer to hold 5-byte address in big-endian byte order
 * @param len Length of array
 */
static inline void address_copyTo(void *bits,unsigned int len, Address *addr)
{
	if (len < ZT_ADDRESS_LENGTH)
		return;
	unsigned char *b = (unsigned char *)bits;
	*(b++) = (unsigned char)((addr->_a >> 32) & 0xff);
	*(b++) = (unsigned char)((addr->_a >> 24) & 0xff);
	*(b++) = (unsigned char)((addr->_a >> 16) & 0xff);
	*(b++) = (unsigned char)((addr->_a >> 8) & 0xff);
	*b = (unsigned char)(addr->_a & 0xff);
}

/**
* Append to a buffer in big-endian byte order
*
* @param b Buffer to append to
*/
static inline void address_appendTo(Buffer *buf, Address *addr)
{	
	unsigned char *p = (unsigned char *)(buf->b + buf->len);
	buf->len += ZT_ADDRESS_LENGTH;
	*(p++) = (unsigned char)((addr->_a >> 32) & 0xff);
	*(p++) = (unsigned char)((addr->_a >> 24) & 0xff);
	*(p++) = (unsigned char)((addr->_a >> 16) & 0xff);
	*(p++) = (unsigned char)((addr->_a >> 8) & 0xff);
	*p = (unsigned char)(addr->_a & 0xff);
}


/**
* @return Hexadecimal string
*/
static inline char *address_toString(Address *addr)
{
	char *buf = (char *)malloc(16);
	snprintf(buf,16,"%.10llx",(unsigned long long)addr->_a);
	return buf;
}

static inline bool address_isReserved(uint64_t _a)
{
	return ((!_a)||((_a >> 32) == ZT_ADDRESS_RESERVED_PREFIX));
}


#endif


