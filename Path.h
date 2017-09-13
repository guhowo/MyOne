#ifndef _ZT_PATH_H
#define _ZT_PATH_H

#include "InetAddress.h"
#include "Buffer.h"

typedef struct _pathKey{
	InetAddress r;
	InetAddress l;
}PathKey;

typedef struct _path{
	InetAddress addr;
	InetAddress localAddress;
	uint64_t lastOut;
	uint64_t lastIn;
	uint64_t lastTrustEstablishedPacketReceived;
	uint64_t incomingLinkQualityFastLog;
	unsigned long incomingLinkQualitySlowLogPtr;
	signed int incomingLinkQualitySlowLogCounter;
	unsigned int incomingLinkQualityPreviousPacketCounter;
	unsigned int outgoingPacketCounter;
	enum IpScope ipScope; // memoize this since it's a computed value checked often
	uint8_t incomingLinkQualitySlowLog[32];
	//AtomicCounter _refCount;
}Path;

bool Path_Send(Path *path,Buffer *buf,uint64_t now);
int Path_Compare(void *new, void *old);

static inline unsigned int nextOutgoingCounter(Path *path)
{
	return path->outgoingPacketCounter++; 
}

/**
* @return True if path has received a trust established packet (e.g. common network membership) in the past 
ZT_TRUST_EXPIRATION ms
*/
static inline bool Path_TrustEstablished(const Path *path,const uint64_t now) 
{
	return ((now - path->lastTrustEstablishedPacketReceived) < ZT_TRUST_EXPIRATION); 
}

static inline bool Path_Alive(Path *path,const uint64_t now)
{
	return ((now - path->lastIn) <= ZT_PATH_ALIVE_TIMEOUT); 
}
bool Path_isAddressValidForPath(const InetAddress *a);

#endif
