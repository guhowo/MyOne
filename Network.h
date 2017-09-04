#ifndef _ZT_NETWORK_H
#define _ZT_NETWORK_H

#include "ZeroTierOne.h"
#include "CertificateOfMembership.h"
#include "NetworkConfig.h"

//#define ZT_NETWORK_MAX_INCOMING_UPDATES 3
//#define ZT_NETWORKCONFIG_DICT_CAPACITY    (1024 + (sizeof(ZT_VirtualNetworkRule) * ZT_MAX_NETWORK_RULES) + (sizeof(Capability) * ZT_MAX_NETWORK_CAPABILITIES) + (sizeof(Tag) * ZT_MAX_NETWORK_TAGS) + (sizeof(CertificateOfOwnership) * ZT_MAX_CERTIFICATES_OF_OWNERSHIP))
//#define ZT_NETWORK_MAX_UPDATE_CHUNKS ((ZT_NETWORKCONFIG_DICT_CAPACITY / 1024) + 1)

typedef uint64_t MAC;

typedef struct _IncomingConfigChunk
{
	uint64_t ts;
	uint64_t updateId;
	uint64_t haveChunkIds[ZT_NETWORK_MAX_UPDATE_CHUNKS];
	unsigned long haveChunks;
	unsigned long haveBytes;
	Dictionary data;
}IncomingConfigChunk;

typedef struct network{	
	uint64_t id;
	uint64_t lastAnnouncedMulticastGroupsUpstream;
	MAC mac; // local MAC address
	bool portInitialized;
/*
	std::vector< MulticastGroup > _myMulticastGroups; // multicast groups that we belong to (according to tap)
	Hashtable< MulticastGroup,uint64_t > _multicastGroupsBehindMe; // multicast groups that seem to be behind us and when we last saw them (if we are a bridge)
	Hashtable< MAC,Address > _remoteBridgeRoutes; // remote addresses where given MACs are reachable (for tracking devices behind remote bridges)
*/
	NetworkConfig config;
	uint64_t lastConfigUpdate;

	IncomingConfigChunk incomingConfigChunks[ZT_NETWORK_MAX_INCOMING_UPDATES];

	bool destroyed;

	enum ncFailure netconfFailure;
	int portError; // return value from port config callback

	//Hashtable<Address,Membership> _memberships;

}NetworkInfo;




#endif
