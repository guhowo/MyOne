#ifndef _ZT_InetAddress_H
#define _ZT_InetAddress_H

#include "list.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <netdb.h>  
#include "Buffer.h"

extern const int port;

enum IpScope{
		IP_SCOPE_NONE = 0,          // NULL or not an IP address
		IP_SCOPE_MULTICAST = 1,     // 224.0.0.0 and other V4/V6 multicast IPs
		IP_SCOPE_LOOPBACK = 2,      // 127.0.0.1, ::1, etc.
		IP_SCOPE_PSEUDOPRIVATE = 3, // 28.x.x.x, etc. -- unofficially unrouted IPv4 blocks often "bogarted"
		IP_SCOPE_GLOBAL = 4,        // globally routable IP address (all others)
		IP_SCOPE_LINK_LOCAL = 5,    // 169.254.x.x, IPv6 LL
		IP_SCOPE_SHARED = 6,        // 100.64.0.0/10, shared space for e.g. carrier-grade NAT
		IP_SCOPE_PRIVATE = 7        // 10.x.x.x, 192.168.x.x, etc.
};

typedef struct _InetAddress{
	struct sockaddr_storage address;
	enum IpScope scope;
}InetAddress;


typedef struct _InetAddressList{
	struct list_head list;
	InetAddress InetAddr;
}InetAddrList;


static inline void InetAddress_Serialize(const InetAddress *InetAddr, Buffer *buf)
{
	// This is used in the protocol and must be the same as describe in places
	// like VERB_HELLO in Packet.hpp.
	switch(InetAddr->address.ss_family) {
		case AF_INET:
			append(buf, (uint8_t)0x04);
			append_databylen(buf, &(((struct sockaddr_in *)(&InetAddr->address))->sin_addr.s_addr), 4);
			append_uint16(buf, (uint16_t)port); // just in case sin_port != uint16_t
			return;
		case AF_INET6:
			append(buf, (uint8_t)0x06);
			append_databylen(buf, &(((struct sockaddr_in6 *)(&InetAddr->address))->sin6_addr.s6_addr), 16);
			append_uint16(buf, (uint16_t)port); // just in case sin_port != uint16_t
			return;
		default:
			append(buf, (uint8_t)0);
			return;
	}
}




static inline unsigned int InetAddress_Deserialize(InetAddress *InetAddr, const unsigned char *b, unsigned int startAt)
{
	unsigned int p = startAt;
	switch(b[p++]) {
		case 0x04:		//IPv4
			InetAddr->address.ss_family = AF_INET;
			memcpy(&(((struct sockaddr_in *)(&InetAddr->address))->sin_addr.s_addr),(b+p), 4); p += 4;	
			memcpy(&(((struct sockaddr_in *)(&InetAddr->address))->sin_port), (b+p), 2); p += 2;
			break;
		case 0x06:		//IPv6
			InetAddr->address.ss_family = AF_INET6;
			memcpy(&(((struct sockaddr_in6 *)(&InetAddr->address))->sin6_addr.s6_addr),(b+p), 16); p += 16;	
			memcpy(&(((struct sockaddr_in *)(&InetAddr->address))->sin_port), (b+p), 2); p += 2;
			break;
		default:
			printf("invalid serialized InetAddress\n");
			break;
	}
	return (p - startAt);
}



static char *InetAddress_toString(const InetAddress *addr)
{
	char *buf = (char *)malloc(128);
	memset(buf, 0, 128);
	switch(addr->address.ss_family) {
		case AF_INET:
			snprintf(buf,128,"%d.%d.%d.%d/%d",
					(int)((const unsigned char *)(&(((const struct sockaddr_in *)addr)->sin_addr.s_addr)))[0],
					(int)((const unsigned char *)(&(((const struct sockaddr_in *)addr)->sin_addr.s_addr)))[1],
					(int)((const unsigned char *)(&(((const struct sockaddr_in *)addr)->sin_addr.s_addr)))[2],
					(int)((const unsigned char *)(&(((const struct sockaddr_in *)addr)->sin_addr.s_addr)))[3],
					(int)ntohs((uint16_t)(((const struct sockaddr_in *)addr)->sin_port)));
			return buf;
		case AF_INET6:
			snprintf(buf,128,"%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x:%.2x%.2x/%d",
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[0]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[1]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[2]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[3]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[4]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[5]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[6]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[7]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[8]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[9]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[10]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[11]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[12]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[13]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[14]),
					(int)(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr[15]),
					(int)ntohs((uint16_t)(((const struct sockaddr_in6 *)addr)->sin6_port))
				);
			return buf;
	}
	return "";
}



#endif

