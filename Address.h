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
typedef uint64_t Address;

/**
* @param bits Raw address -- 5 bytes, big-endian byte order
* @param len Length of array
*/
void Address_SetTo(const void *bits,unsigned int len, Address *addr);

/**
 * @param bits Buffer to hold 5-byte address in big-endian byte order
 * @param len Length of array
 */
void Address_CopyTo(void *bits,unsigned int len, Address addr);

/**
* Append to a buffer in big-endian byte order
*
* @param b Buffer to append to
*/
void Address_AppendTo(Buffer *buf, Address addr);


/**
* @return Hexadecimal string
*/
char *Address_ToString(Address addr);

bool Address_IsReserved(Address a);


#endif


