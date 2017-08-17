#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include<sys/types.h>
#include<fcntl.h> 
#include <arpa/inet.h>
#ifdef __LINUX__
#include <sys/syscall.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>


#include "Utils.h"

uint64_t now()
{
	struct timeval tv;
#ifdef __LINUX__
		syscall(SYS_gettimeofday,&tv,0); /* fix for musl libc broken gettimeofday bug */
#else
		gettimeofday(&tv,(struct timezone *)0);
#endif
	return ( (1000ULL * (uint64_t)tv.tv_sec) + (uint64_t)(tv.tv_usec / 1000) );
}

void getSecureRandom(void *buf,unsigned int bytes)
{
	static Salsa20 s20;
	static int s20Initialized = false;
	static uint8_t randomBuf[65536];
	static unsigned int randomPtr = sizeof(randomBuf);
	unsigned int i = 0;


	/* Just for posterity we Salsa20 encrypt the result of whatever system
	 * CSPRNG we use. There have been several bugs at the OS or OS distribution
	 * level in the past that resulted in systematically weak or predictable
	 * keys due to random seeding problems. This mitigates that by grabbing
	 * a bit of extra entropy and further randomizing the result, and comes
	 * at almost no cost and with no real downside if the random source is
	 * good. */
	if (!s20Initialized) {
		s20Initialized = true;
		uint64_t s20Key[4];
		s20Key[0] = (uint64_t)time(0); // system clock
		s20Key[1] = (uint64_t)buf; // address of buf
		s20Key[2] = (uint64_t)s20Key; // address of s20Key[]
		s20Key[3] = (uint64_t)&s20; // address of s20
		Salsa20_init(&s20, s20Key,s20Key);
	}

	static int devURandomFd = -1;

	if (devURandomFd < 0) {
		devURandomFd = open("/dev/urandom", O_RDONLY);
		if (devURandomFd < 0) {
			fprintf(stderr,"FATAL ERROR: Utils::getSecureRandom() unable to open /dev/urandom\n");
			exit(1);
			return;
		}
	}

	for(i=0;i<bytes;++i) {
		if (randomPtr >= sizeof(randomBuf)) {
			for(;;) {
				if ((int)read(devURandomFd,randomBuf,sizeof(randomBuf)) != (int)sizeof(randomBuf)) {
					close(devURandomFd);
					devURandomFd = open("/dev/urandom",O_RDONLY);
					if (devURandomFd < 0) {
						fprintf(stderr,"FATAL ERROR: Utils::getSecureRandom() unable to open /dev/urandom\n");
						exit(1);
						return;
					}
				} else break;
			}
			randomPtr = 0;
			Salsa20_crypt12(&s20, randomBuf,randomBuf,sizeof(randomBuf));
			Salsa20_init(&s20, randomBuf,randomBuf);
		}
		((uint8_t *)buf)[i] = randomBuf[randomPtr++];
	}

}



uint64_t Utils_hton_u64(uint64_t n)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
#if defined(__GNUC__) && (!defined(__OpenBSD__))
	return __builtin_bswap64(n);
#else
	return (
		((n & 0x00000000000000FFULL) << 56) |
		((n & 0x000000000000FF00ULL) << 40) |
		((n & 0x0000000000FF0000ULL) << 24) |
		((n & 0x00000000FF000000ULL) <<  8) |
		((n & 0x000000FF00000000ULL) >>  8) |
		((n & 0x0000FF0000000000ULL) >> 24) |
		((n & 0x00FF000000000000ULL) >> 40) |
		((n & 0xFF00000000000000ULL) >> 56)
	);
#endif
#else
	return n;
#endif
}

uint64_t Utils_ntoh_u64(uint64_t n)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
#if defined(__GNUC__) && !defined(__OpenBSD__)
	return __builtin_bswap64(n);
#else
	return (
		((n & 0x00000000000000FFULL) << 56) |
		((n & 0x000000000000FF00ULL) << 40) |
		((n & 0x0000000000FF0000ULL) << 24) |
		((n & 0x00000000FF000000ULL) <<  8) |
		((n & 0x000000FF00000000ULL) >>  8) |
		((n & 0x0000FF0000000000ULL) >> 24) |
		((n & 0x00FF000000000000ULL) >> 40) |
		((n & 0xFF00000000000000ULL) >> 56)
	);
#endif
#else
	return n;
#endif
}

bool Utils_secureEq(const void *a,const void *b,unsigned int len)
{
	uint8_t diff = 0;
	unsigned int i;
	for(i=0;i<len;++i)
		diff |= ( ((const uint8_t *)(a))[i] ^ ((const uint8_t *)(b))[i] );
	return (diff == 0);
}

unsigned int Utils_unhex(const char *hex,unsigned int maxlen,void *buf,unsigned int len)
{
	int n = 1;
	unsigned char c,b = 0;
	unsigned int l = 0;
	const char *eof = hex + maxlen;

	if (!maxlen)
		return 0;

	while ((c = (unsigned char)*(hex++))) {
		if ((c >= 48)&&(c <= 57)) { // 0..9
			if ((n ^= 1)) {
				if (l >= len) break;
				((unsigned char *)buf)[l++] = (b | (c - 48));
			} else b = (c - 48) << 4;
		} else if ((c >= 65)&&(c <= 70)) { // A..F
			if ((n ^= 1)) {
				if (l >= len) break;
				((unsigned char *)buf)[l++] = (b | (c - (65 - 10)));
			} else b = (c - (65 - 10)) << 4;
		} else if ((c >= 97)&&(c <= 102)) { // a..f
			if ((n ^= 1)) {
				if (l >= len) break;
				((unsigned char *)buf)[l++] = (b | (c - (97 - 10)));
			} else b = (c - (97 - 10)) << 4;
		}
		if (hex == eof)
			break;
	}

	return l;
}



