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
}Moons;

typedef struct _Peernode{
	Address address;
	Peer peer;
	Identity id;
	InetAddrList *pInetAddress;		//readOnly
}PeerNode;

typedef struct _topology{
	World planet;
	Moons moons;
	upstreamAddress upstreamAddresses;
	bool amRoot;
}Topology;


typedef struct _CertificateOfRepresentation{
	Address reps[ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES];
	unsigned int repCount;
	uint64_t _timestamp;
	Signature _signature;
}CertificateOfRepresentation;

void Topology_Init(void);
unsigned int Topology_Deserialize(World *newWorld, Roots *newRoot, const unsigned char *b,unsigned int startAt);
void Topology_Serialize(Buffer * buf, bool forSign);
bool Topology_AddWorld(World *defaultPlanet,bool flag);
Peer *Topology_AddPeer(Peer *peer);
PeerNode *Topology_GetPeerNode(Address addr);

/**
 * @return Current certificate of representation (copy)
 */
void Topology_AppendCor(Buffer * buf);
unsigned int Certificate_Deserialize(CertificateOfRepresentation *cor,const unsigned char *data, unsigned int len,unsigned int startAt);
Path *Topology_GetPath(const InetAddress *local, const InetAddress *remote);
bool Topology_IsInUpstreams(const Address *addr);


#endif
