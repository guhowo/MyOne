#ifndef ZT_UTILS_H
#define ZT_UTILS_H

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdint.h>

#include "salsa20.h"

#define false 0
#define true 1
#define bool int

/**
 * @return Current time in milliseconds since epoch
 */
uint64_t now();

void getSecureRandom(void *buf,unsigned int bytes);
bool Utils_secureEq(const void *a,const void *b,unsigned int len);
uint64_t Utils_ntoh_u64(uint64_t n);
uint64_t Utils_hton_u64(uint64_t n);
char *Utils_hex(const void *data,unsigned int len);
unsigned int Utils_unhex(const char *hex,unsigned int maxlen,void *buf,unsigned int len);
unsigned long long Utils_strToU64(const char *s);
unsigned int long long Utils_hexStrToU64(const char *s);

#endif
