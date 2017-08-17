#ifndef _ZT_TOPOLOGY_H
#define _ZT_TOPOLOGY_H

#include <stdio.h>
#include "Packet.h"
#include "World.h"
#include "Address.h"
#include "Identity.h"
#include "InetAddress.h"
#include "list.h"
#include "Peer.h"
#include "Buffer.h"
#include "C25519.h"
#include "Path.h"

#define ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES ZT_MAX_UPSTREAMS

typedef struct _upstreamAddress_{
	struct list_head list;
	Address addr;
}upstreamAddress;

typedef struct _MoonsList{
	struct list_head list;
	World moon;
}MoonsList;

typedef struct _Peernode{
	Address address;
	Peer peer;
	Identity id;
	InetAddrList *pInetAddress;		//readOnly
}PeerNode;

typedef struct _UpstreamsToContact{
	struct list_head list;
	Address ztAddr;
	InetAddrList inetAddrs;
}UpstreamsToContact;


typedef struct _topology{
//	RuntimeEnvironment RR;
	World planet;
	MoonsList moons;
	upstreamAddress upstreamAddresses;
	bool amRoot;
}Topology;


typedef struct _CertificateOfRepresentation{
	Address reps[ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES];
	unsigned int repCount;
	uint64_t _timestamp;
	Signature _signature;
}CertificateOfRepresentation;

void init_topology(void);
unsigned int topology_deserialize(World *newWorld, Roots *newRoot, const unsigned char *b,unsigned int startAt);
void Topology_serialize(Buffer * buf, bool forSign);
bool addWorld(World *defaultPlanet,bool flag);
Peer *addPeer(Peer *peer);
PeerNode *getPeerNodeByAddress(Address *addr);
void Topology_appendCertificateOfRepresentation(Buffer * buf);
unsigned int certificate_deserialize(CertificateOfRepresentation *cor,const unsigned char *data, unsigned int len,unsigned int startAt);
Path *getPath(const InetAddress *local, const InetAddress *remote);
bool shouldAcceptWorldUpdateFrom(const Address *addr);

#endif
