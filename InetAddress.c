#include "InetAddress.h"

unsigned int InetAddress_netmaskBits(const InetAddress *addr)
{
	switch(addr->address.ss_family) {
		case AF_INET: return ntohs((uint16_t)(((const struct sockaddr_in *)addr)->sin_port));
		case AF_INET6: return ntohs((uint16_t)(((const struct sockaddr_in6 *)addr)->sin6_port));
		default: return 0;
	}
}

InetAddress _netmask(const InetAddress *self,const InetAddress *addr)
{
	InetAddress r;
	memcpy(&r,self,sizeof(r));
	switch(r.address.ss_family) {
		case AF_INET:
			((struct sockaddr_in *)&r)->sin_addr.s_addr = htonl((uint32_t)(0xffffffff << (32 - InetAddress_netmaskBits(addr))));
			break;
		case AF_INET6: {
			uint64_t nm[2];
			const unsigned int bits = InetAddress_netmaskBits(addr);
            if(bits) {
                nm[0] = Utils_hton_u64((uint64_t)((bits >= 64) ? 0xffffffffffffffffULL : (0xffffffffffffffffULL << (64 - bits))));
                nm[1] = Utils_hton_u64((uint64_t)((bits <= 64) ? 0ULL : (0xffffffffffffffffULL << (128 - bits))));
            }
            else {
                nm[0] = 0;
                nm[1] = 0;
            }
			memcpy(&(((struct sockaddr_in6 *)&r)->sin6_addr.s6_addr),nm,16);
		}	break;
	}
	return r;
}

bool InetAddress_containsAddress(const InetAddress *self,const InetAddress *addr)
{
	if (addr->address.ss_family == self->address.ss_family) {
		switch(self->address.ss_family) {
			case AF_INET: {
				const unsigned int bits = InetAddress_netmaskBits(self);
				if (bits == 0)
					return true;
				return ((ntohl((uint32_t)(((const struct sockaddr_in *)addr)->sin_addr.s_addr)) >> (32 - bits)) == (ntohl((uint32_t)(((const struct sockaddr_in *)self)->sin_addr.s_addr)) >> (32 - bits)));
			}
			case AF_INET6: {
				InetAddress mask;
				_netmask(&mask,addr);
				const uint8_t *m = (const uint8_t *)&(((const struct sockaddr_in6 *)&mask)->sin6_addr.s6_addr);
				const uint8_t *a = (const uint8_t *)&(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr);
				const uint8_t *b = (const uint8_t *)&(((const struct sockaddr_in6 *)self)->sin6_addr.s6_addr);
				unsigned int i;
				for(i=0;i<16;++i) {
					if ((a[i] & m[i]) != b[i])
						return false;
				}
				return true;
			}
		}
	}
	return false;
}

void InetAddress_setPort(unsigned int port, InetAddress *addr)
{
	switch(addr->address.ss_family) {
		case AF_INET:
			((struct sockaddr_in *)addr)->sin_port = htons((uint16_t)port);
			break;
		case AF_INET6:	
			((struct sockaddr_in6 *)addr)->sin6_port = htons((uint16_t)port);
			break;
	}
}

const void *InetAddress_rawIpData(InetAddress *addr)
{
	switch(addr->address.ss_family) {
		case AF_INET: return (const void *)&(((const struct sockaddr_in *)addr)->sin_addr.s_addr);
		case AF_INET6: return (const void *)&(((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr);
		default: return 0;
	}
}

bool InetAddress_compare(const InetAddress *a, const InetAddress *b)
{
	if (a->address.ss_family == b->address.ss_family) {
		switch(a->address.ss_family) {
			case AF_INET:
				return (
					(((const struct sockaddr_in *)a)->sin_port == ((const struct sockaddr_in *)b)->sin_port)&&
					(((const struct sockaddr_in *)a)->sin_addr.s_addr == ((const struct sockaddr_in *)b)->sin_addr.s_addr));
				break;
			case AF_INET6:
				return (
					(((const struct sockaddr_in6 *)a)->sin6_port == ((const struct sockaddr_in6 *)b)->sin6_port)&&
					(((const struct sockaddr_in6 *)a)->sin6_flowinfo == ((const struct sockaddr_in6 *)b)->sin6_flowinfo)&&
					(memcmp(&(((const struct sockaddr_in6 *)a)->sin6_addr.s6_addr),&(((const struct sockaddr_in6 *)b)->sin6_addr.s6_addr),16) == 0)&&
					(((const struct sockaddr_in6 *)a)->sin6_scope_id == ((const struct sockaddr_in6 *)b)->sin6_scope_id));
				break;
			default:
				return (memcmp(a,b,sizeof(InetAddress)) == 0);
		}
	}
	return false;

}


void InetAddress_Serialize(const InetAddress *InetAddr, Buffer *buf)
{
	// This is used in the protocol and must be the same as describe in places
	// like VERB_HELLO in Packet.hpp.
	switch(InetAddr->address.ss_family) {
		case AF_INET:
			append(buf, (uint8_t)0x04);
			append_databylen(buf, &(((struct sockaddr_in *)(&InetAddr->address))->sin_addr.s_addr), 4);
			append_uint16(buf, (uint16_t)InetAddress_netmaskBits(InetAddr)); // just in case sin_port != uint16_t
			return;
		case AF_INET6:
			append(buf, (uint8_t)0x06);
			append_databylen(buf, &(((struct sockaddr_in6 *)(&InetAddr->address))->sin6_addr.s6_addr), 16);
			append_uint16(buf, (uint16_t)InetAddress_netmaskBits(InetAddr)); // just in case sin_port != uint16_t
			return;
		default:
			append(buf, (uint8_t)0);
			return;
	}
}


