#include <netinet/in.h>
#include "Utils.h"
#include "Packet.h"
#include "Path.h"

bool Path_send(Path *path,Buffer *buf,uint64_t now)
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

int Path_compare(void *newPath, void *oldPath)
{
	uint64_t newKey[4] = {0};
	uint64_t oldKey[4] = {0};
	HashKey(newKey, &((PathKey *)newPath)->l, &((PathKey *)newPath)->r);
	HashKey(oldKey, &((PathKey *)oldPath)->l, &((PathKey *)oldPath)->r);

	return memcmp(newKey,oldKey,sizeof(oldKey));
	
}

