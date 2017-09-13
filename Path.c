#include <netinet/in.h>
#include "Utils.h"
#include "Packet.h"
#include "Path.h"

bool Path_Send(Path *path,Buffer *buf,uint64_t now)
{
	if(udpSend((const struct sockaddr *)&(path->addr.address),buf)) {
		path->lastOut = now;
		return true;
	}
	return false;
}

void HashKey(uint64_t *key,const InetAddress *l,const InetAddress *r)
{
	if (r->address.ss_family == AF_INET) {
		key[0] = (uint64_t)((struct sockaddr_in *)r)->sin_addr.s_addr;
		key[1] = (uint64_t)((struct sockaddr_in *)r)->sin_port;
		if (l->address.ss_family == AF_INET) {
			key[2] = (uint64_t)((struct sockaddr_in *)l)->sin_addr.s_addr;
			key[3] = (uint64_t)((struct sockaddr_in *)l)->sin_port;
		} else {
			key[2] = 0;
			key[3] = 0;
		}
	}else {
		key[0] = 0;
		key[1] = 0;
		key[2] = 0;
		key[3] = 0;
	}
}

int Path_Compare(void *newPath, void *oldPath)
{
	uint64_t newKey[4] = {0};
	uint64_t oldKey[4] = {0};
	HashKey(newKey, &((PathKey *)newPath)->l, &((PathKey *)newPath)->r);
	HashKey(oldKey, &((PathKey *)oldPath)->l, &((PathKey *)oldPath)->r);

	return memcmp(newKey,oldKey,sizeof(oldKey));
	
}

bool Path_isAddressValidForPath(const InetAddress *a)
{
	if ((a->address.ss_family == AF_INET)||(a->address.ss_family == AF_INET6)) {
		switch(InetAddress_ipScope(a)) {
			/* Note: we don't do link-local at the moment. Unfortunately these
			 * cause several issues. The first is that they usually require a
			 * device qualifier, which we don't handle yet and can't portably
			 * push in PUSH_DIRECT_PATHS. The second is that some OSes assign
			 * these very ephemerally or otherwise strangely. So we'll use
			 * private, pseudo-private, shared (e.g. carrier grade NAT), or
			 * global IP addresses. */
			case IP_SCOPE_PRIVATE:
			case IP_SCOPE_PSEUDOPRIVATE:
			case IP_SCOPE_SHARED:
			case IP_SCOPE_GLOBAL:
				if (a->address.ss_family == AF_INET6) {
					// TEMPORARY HACK: for now, we are going to blacklist he.net IPv6
					// tunnels due to very spotty performance and low MTU issues over
					// these IPv6 tunnel links.
					const uint8_t *ipd = (const uint8_t *)(((const struct sockaddr_in6 *)a)->sin6_addr.s6_addr);
					if ((ipd[0] == 0x20)&&(ipd[1] == 0x01)&&(ipd[2] == 0x04)&&(ipd[3] == 0x70))
						return false;
				}
				return true;
			default:
				return false;
		}
	}
	return false;
}


