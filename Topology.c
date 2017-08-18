#include "Topology.h"
#include "InetAddress.h"
#include <string.h>
#include <stdio.h>
#include "RuntimeEnvironment.h"
#include "Utils.h"
#include "Identity.h"
#include "C25519.h"

#define ZT_DEFAULT_WORLD_LENGTH 336
static const unsigned char ZT_DEFAULT_WORLD[ZT_DEFAULT_WORLD_LENGTH] = {0x01,0x00,0x00,0x00,0x61,0xa7,0x18,0x14,0x61,0x00,0x00,0x01,0x5c,0xf3,0xb5,0x0d,0xa4,0x49,0x29,0x47,0xea,0x0b,0x9d,0x2a,0xf1,0x40,0xea,0x46,0x8f,0x26,0x60,0xb8,0x38,0xcf,0x8a,0xa7,0x6d,0x9f,0xd8,0x60,0xdc,0xcd,0x1c,0x10,0xaa,0xc3,0xdb,0x8a,0x6e,0x5f,0x61,0x34,0x5e,0x68,0xb7,0x05,0x5c,0xae,0xc6,0x15,0x64,0x68,0x39,0x47,0x0f,0xc3,0xcb,0xc0,0x11,0x0d,0x15,0xcd,0xf8,0xeb,0xdd,0xd6,0xb7,0x13,0x51,0xb0,0x31,0xb3,0xf6,0x85,0x48,0x38,0xfa,0x2b,0xf9,0x78,0x34,0x68,0x5f,0xe6,0xe3,0x35,0xc8,0xe5,0x8e,0x52,0x44,0x22,0x24,0x32,0x52,0x3a,0x29,0x6b,0x7e,0x3e,0x6f,0x0d,0x91,0xac,0x72,0xc6,0xab,0xaf,0x21,0xb4,0xa8,0x74,0xd3,0x81,0x5b,0x5c,0x8e,0x63,0x8c,0x0a,0x74,0x7f,0x3d,0x9c,0x24,0x82,0x1e,0x83,0x65,0x8d,0x43,0xdc,0x9d,0xff,0x0a,0xc5,0x90,0x63,0x3c,0x90,0xde,0xc6,0xde,0xe4,0x85,0xd5,0x06,0x85,0x69,0x18,0x98,0x32,0x4a,0x95,0xc5,0xac,0x08,0x9c,0x70,0x5c,0xb4,0x28,0xa9,0xd1,0x58,0xd6,0xbd,0x02,0x61,0xa7,0x18,0x14,0x61,0x00,0x5e,0x5f,0xb8,0xe1,0xb5,0x58,0x67,0xd5,0x0c,0x79,0x09,0xa7,0x0d,0xf8,0x4f,0xdb,0x8f,0x32,0x63,0x21,0xef,0xb5,0x5d,0xe8,0xda,0x96,0x7a,0xdb,0xde,0x12,0x0b,0x67,0x94,0x1e,0x0a,0xb3,0xc6,0x9c,0xf3,0x82,0xe7,0x66,0x69,0x53,0x6f,0x3d,0xe3,0xb3,0x20,0x7e,0x3b,0x2c,0x71,0x4a,0xaf,0x1a,0x27,0xcb,0x3e,0xfb,0x6e,0xd1,0x22,0x64,0x00,0x01,0x04,0x77,0x17,0xed,0x24,0x11,0x5b,0x61,0xf8,0x50,0x00,0x61,0x00,0x68,0xc0,0xd0,0x1e,0x46,0x6d,0x1c,0x5b,0x2a,0xe1,0x2c,0x79,0x02,0x75,0x9b,0x51,0x3d,0xc1,0x7c,0xe5,0x29,0xcb,0x4e,0xac,0xc3,0x59,0xf3,0xb5,0xda,0x8c,0x69,0x31,0xd4,0xb0,0x7c,0x83,0x30,0x32,0x1a,0x5d,0x9c,0x43,0x56,0x2a,0x3f,0xff,0xea,0x4c,0x56,0x12,0x04,0x36,0x25,0x94,0xd7,0x81,0x89,0x71,0x75,0x25,0xeb,0x5f,0x2a,0x0f,0x00,0x01,0x04,0x77,0x17,0xe2,0x6a,0x11,0x5b};


static CertificateOfRepresentation CRepresentation;
Roots *pRoots = NULL;
Topology topy; 

static upstreamAddress *pupstreams = &(topy.upstreamAddresses);
extern RuntimeEnvironment *RR;


bool findUpstream(Address addr)
{
	upstreamAddress *tmp;
	list_for_each_entry(tmp, &pupstreams->list, list) {
		if(tmp->addr == addr)
			return true;
	}
	return false;
}


bool findPeer(Address addr)
{
	return (avl_locate(RR->addrTree, (void *)&addr) != NULL);
}

static bool findStableEndpoints(InetAddress *addr, InetAddrList *iAddrlist)
{
	InetAddrList *tmp;
	list_for_each_entry(tmp, &iAddrlist->list, list) {
		if(memcmp(&tmp->InetAddr.address, &addr->address, sizeof(InetAddress)) == 0) {
			return true;
		}
	}
	return false;
}

static void certificate_serialize(Buffer * buf, bool forSign){
	unsigned int i = 0;
	if (forSign){
		append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}

	append_uint64(buf, (uint64_t)CRepresentation._timestamp);
	append_uint16(buf, (uint16_t)CRepresentation.repCount);
	for(i = 0;i < CRepresentation.repCount; ++i){
		Address_AppendTo(buf, CRepresentation.reps[i]);
	}

	if (!forSign) {
		append(buf, (uint8_t)1); // 1 == Ed25519 signature
		append_uint16(buf, (uint16_t)ZT_C25519_SIGNATURE_LEN);
		append_databylen(buf, CRepresentation._signature,ZT_C25519_SIGNATURE_LEN);
	}

	append_uint16(buf, (uint16_t)0); // size of any additional fields, currently 0

	if (forSign){
		append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}
}

unsigned int Certificate_Deserialize(CertificateOfRepresentation *cor,const unsigned char *data, unsigned int len,unsigned int startAt)
{
	memset(&cor,0,sizeof(cor));

	unsigned int p = startAt;

	cor->_timestamp = Utils_ntoh_u64(((uint64_t *)data)[p]); 
	p += 8;
	const unsigned int rc = (unsigned int)ntohs(((uint16_t *)data)[p]);
	p += 2;
	unsigned int i;
	for(i=0;i<rc;++i) {
		if (i < ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES)
			Address_SetTo(data,ZT_ADDRESS_LENGTH,&cor->reps[i]);
		p += ZT_ADDRESS_LENGTH;
	}
	cor->repCount = (rc > ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES) ? ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES : rc;

	if (data[p++] == 1) {
		if (ntohs(((uint16_t *)data)[p]) == ZT_C25519_SIGNATURE_LEN) {
			p += 2;
			memcpy(cor->_signature,&data[p],ZT_C25519_SIGNATURE_LEN);
			p += ZT_C25519_SIGNATURE_LEN;
		} else {
			printf("invalid signature\n");
			exit(1);
		}
	} else {
		p += 2 + ntohs(((uint16_t *)data)[p]);
	}

	p += 2 + ntohs(((uint16_t *)data)[p]);
	if (p > len) {
		printf("extended field overflow\n");
		exit(1);
	}

	return (p - startAt);
}

void Certificate_sign(const Identity *myIdentity,const uint64_t ts)
{
	Buffer tmp;
	Buffer_Init(&tmp);
	CRepresentation._timestamp = ts;
	certificate_serialize(&tmp,true);
	C25519_sign4(CRepresentation._signature, myIdentity->_privateKey, myIdentity->_publicKey, tmp.b, tmp.len);
}

void Topology_Serialize(Buffer * buf, bool forSign)
{
	World *pTmpWorld = &(RR->pTopology->planet);
	Roots *pTmpRoots = NULL;
	InetAddrList *pTmpInetAddr = NULL;
	unsigned char rootNum = 0;
	unsigned char endpointNum = 0;
	int posRoot = 0;
	int posEndpoint = 0;
	
	if (forSign){
		append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}

	append(buf, (uint8_t)pTmpWorld->type);
	append_uint64(buf, (uint64_t)pTmpWorld->id);
	append_uint64(buf, (uint64_t)pTmpWorld->ts);
	append_databylen(buf,  (void *)pTmpWorld->updatesMustBeSignedBy, ZT_C25519_PUBLIC_KEY_LEN);
	if (!forSign){
		append_databylen(buf, (void *)pTmpWorld->signature, ZT_C25519_SIGNATURE_LEN);
	}

	posRoot = buf->len++;
	
	list_for_each_entry(pTmpRoots, &(pTmpWorld->roots.list), list){
		rootNum++;
		Identity_Serialize(&(pTmpRoots->root.identity), buf, false);
		posEndpoint = buf->len++;
		list_for_each_entry(pTmpInetAddr, &(pTmpRoots->root.stableEndpoints.list), list){
			endpointNum++;
			InetAddress_Serialize(&(pTmpInetAddr->InetAddr), buf);
		}
		buf->b[posEndpoint] = endpointNum;
	}
	buf->b[posRoot] = (uint8_t)rootNum;
	if (pTmpWorld->type == TYPE_MOON){
		append_uint16(buf, 0);// no attached dictionary (for future use)
	} 

	if (forSign){
		append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}
}

unsigned int Topology_Deserialize(World *newWorld, Roots *newRootHead, const unsigned char *b,unsigned int startAt)
{
	unsigned int p = startAt;

	switch((enum Type)b[p++]) {
		case TYPE_NULL: newWorld->type = TYPE_NULL; break; // shouldn't ever really happen in serialized data but it's not invalid
		case TYPE_PLANET: newWorld->type = TYPE_PLANET; break;
		case TYPE_MOON: newWorld->type = TYPE_MOON; break;
		default: printf("invalid world type");	exit(1);
	}

	newWorld->id = Utils_ntoh_u64(*(uint64_t *)&b[p]); //*((uint64_t *)(b+p))
	p += 8;
	newWorld->ts = Utils_ntoh_u64(*(uint64_t *)&b[p]); 	
	p += 8;
	memcpy(newWorld->updatesMustBeSignedBy, b+p, sizeof(newWorld->updatesMustBeSignedBy)); 
	p += sizeof(newWorld->updatesMustBeSignedBy);
	memcpy(newWorld->signature, b+p, sizeof(newWorld->signature)); 
	p += sizeof(newWorld->signature);
	const unsigned int numRoots = (unsigned int)b[p++];
	if (numRoots > ZT_WORLD_MAX_ROOTS) {
		printf("too many roots in World");	
		exit(2);
	}
	
	unsigned int k;
	for(k=0;k<numRoots;++k) {
		Roots *r = (Roots *)malloc(sizeof(Roots));
		p += Identity_Deserialize(&(r->root.identity),b,p);	//initialize root->identity
		unsigned int numStableEndpoints = b[p++];
		if (numStableEndpoints > ZT_WORLD_MAX_STABLE_ENDPOINTS_PER_ROOT) {
			printf("too many stable endpoints in World/Root\n");
			exit(2);
		}
		unsigned int kk;
		INIT_LIST_HEAD(&r->root.stableEndpoints.list); 		//initialize roots list
		for(kk=0;kk<numStableEndpoints;++kk) {
			InetAddrList *iAddr = (InetAddrList *)malloc(sizeof(InetAddrList));
			p += InetAddress_Deserialize(&iAddr->InetAddr, b, p);
			r->root.stableEndpoints.InetAddr = iAddr->InetAddr;
			list_add_tail(&(iAddr->list), &(r->root.stableEndpoints.list));
		}
		list_add_tail(&(r->list), &(newRootHead->list));
	}
	if (newWorld->type == TYPE_MOON)
		p += (unsigned int)ntohs(*(uint16_t*)&b[p]) + 2;

	return (p - startAt);
}

void memoizeUpstreams(World *world)
{
	Roots *proots = &world->roots;
	Roots *tmp;
	upstreamAddress *tmpStream = NULL;
	
	list_for_each_entry(tmp, &proots->list, list) {
		if(Identity_IsEqual(&tmp->root.identity, &RR->identity)) {
			topy.amRoot = true;
		} else if(!findUpstream(tmp->root.identity._address)) {
			tmpStream = (upstreamAddress *)malloc(sizeof(upstreamAddress));
			tmpStream->addr = tmp->root.identity._address; 
			list_add_tail(&tmpStream->list, &pupstreams->list);
			
			if(!findPeer(tmp->root.identity._address)) {
				PeerNode *tmpPeer = (PeerNode *)malloc(sizeof(PeerNode));
				memset(tmpPeer, 0, sizeof(PeerNode));
				tmpPeer->address = tmp->root.identity._address;
				Peer_Init(&tmpPeer->peer, &(tmp->root.identity));
				memcpy(&tmpPeer->id, &tmpPeer->peer.id, sizeof(Identity));
				tmpPeer->pInetAddress = &tmp->root.stableEndpoints; //only for read,do not write
				avl_insert(RR->addrTree, (void *)tmpPeer);
			}
		}
	}

	/**
	***moons to upstreams
	**/

	list_for_each_entry(tmpStream, &pupstreams->list, list) {
		if (CRepresentation.repCount < ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES) {
			CRepresentation.reps[CRepresentation.repCount++] = tmpStream->addr;
			continue;
		}
		break;
	}
	memset(&CRepresentation, 0, sizeof(CRepresentation));
	Certificate_sign(&RR->identity,now());		////when get the _now
	
}


bool Topology_AddWorld(World *newWorld, bool alwaysAcceptNew)
{
	if ((newWorld->type != TYPE_PLANET)&&(newWorld->type != TYPE_MOON))
			return false;

	memoizeUpstreams(newWorld);
	
	return true;
}

Peer *Topology_AddPeer(Peer *peer)
{
	PeerNode *np = NULL;
	np = (PeerNode *)avl_locate(RR->addrTree, &peer->id._address);
	
	if(!np) {
		np = (PeerNode *)malloc(sizeof(PeerNode));
		memset(np, 0, sizeof(PeerNode));
		memcpy(&np->peer, peer, sizeof(Peer));
		memcpy(&np->address, &peer->id._address, sizeof(Address));
		memcpy(&np->id, &peer->id, sizeof(peer->id));
		avl_insert(RR->addrTree,(void *)np);
	}

	//save identity to local db

	return &np->peer;
}

void Topology_Init(void)
{	
	RR->pTopology = &topy;
	memset(&topy, 0, sizeof(topy));
	pRoots = &(topy.planet.roots);
	INIT_LIST_HEAD(&pRoots->list); 		//initialize roots list
	
	Topology_Deserialize(&(topy.planet), pRoots, ZT_DEFAULT_WORLD, 0);
	INIT_LIST_HEAD(&(pupstreams->list));
	
	Topology_AddWorld(&(topy.planet), false);
}

void Topology_AppendCor(Buffer * buf){
		certificate_serialize(buf, false);
}

Path *Topology_GetPath(const InetAddress *local, const InetAddress *remote){
	Path *p = NULL;
	PathKey key;

	memcpy(&(key.r), remote, sizeof(InetAddress));
	memcpy(&(key.l), local, sizeof(InetAddress));

	p = avl_locate(RR->pathsTree, (void *)&key);
	if(!p){
		p = malloc(sizeof(Path));
		memcpy(&(p->addr), remote, sizeof(InetAddress));
		memcpy(&(p->localAddress), local, sizeof(InetAddress));
		avl_insert(RR->pathsTree, (void *)p);
	}
	
	return p;
}


bool Topology_IsInUpstreams(const Address *addr)
{	
	if (findUpstream(*addr))
		return true;
	return false;
}

PeerNode *Topology_GetPeerNode(Address addr){
	PeerNode * p = NULL;
	p = avl_locate(RR->addrTree, (void *)&addr);
	if(!p){
		printf("get peernode by address failed\n");	
		return NULL;
	}
	return p;

}

