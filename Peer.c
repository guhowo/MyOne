#include "avl_local.h"
#include "Peer.h"
#include "RuntimeEnvironment.h"
#include "C25519.h"

extern RuntimeEnvironment *RR;

void Peer_Init(Peer *p, Identity *peerId){
	C25519_agree(RR->identity._privateKey, peerId->_publicKey, p->key, ZT_PEER_SECRET_KEY_LENGTH);
	memcpy(&(p->id), peerId, sizeof(Identity));
}

Peer *Peer_GotByAddress(Address addr)
{
	PeerNode * p = NULL;
	p = avl_locate(RR->addrTree, (void *)&addr);
	if(!p){
		printf("get peer by address failed.\n");	
		return NULL;
	}
	printf("get peer by address successfully\n");	
	return &(p->peer);
}

void setRemoteVersion(Peer *peer,unsigned int vproto,unsigned int vmaj,unsigned int vmin,unsigned int vrev)
{
	peer->vProto = (uint16_t)vproto;
	peer->vMajor = (uint16_t)vmaj;
	peer->vMinor = (uint16_t)vmin;
	peer->vRevision = (uint16_t)vrev;
}

void attemptToContactAt(Peer *peer,InetAddress *localAddr,InetAddress *atAddress,uint64_t now,bool sendFullHello,unsigned int counter)
{
	//need to do 
	sendHELLO(peer,localAddr,atAddress,now,counter);
}

void received(Peer *peer,	Path *path,const unsigned int hops,const uint64_t packetId,const enum Verb verb,const uint64_t inRePacketId,const enum Verb inReVerb,const bool trustEstablished)
{
	const uint64_t now = RR->now;
	peer->lastReceive = now;
	switch (verb) {
		case VERB_FRAME:
		case VERB_EXT_FRAME:
		case VERB_NETWORK_CONFIG_REQUEST:
		case VERB_NETWORK_CONFIG:
		case VERB_MULTICAST_FRAME:
			peer->lastNontrivialReceive = now;
			break;
		default: break;
	}
	
	if (trustEstablished) {
		peer->lastTrustEstablishedPacketReceived = now;
		path->lastTrustEstablishedPacketReceived = now;
	}

	if (peer->vProto >= 9) {
		//path->updateLinkQuality((unsigned int)(packetId & 7));
	}

	if(hops == 0) {
		bool pathAlreadyKnown = false;
		if ((path->addr.address.ss_family == AF_INET)&&(peer->v4Path.p)) {
			struct sockaddr_in r;
			memcpy(&r, (struct sockaddr_in *)(&path->addr), sizeof(r));
			struct sockaddr_in l;
			memcpy(&l, (struct sockaddr_in *)(&peer->v4Path.p->addr), sizeof(l));
			struct sockaddr_in rl;
			memcpy(&rl, (struct sockaddr_in *)(&path->localAddress), sizeof(rl));
			struct sockaddr_in ll;
			memcpy(&ll, (struct sockaddr_in *)(&peer->v4Path.p->localAddress),sizeof(ll));
			if ((memcmp(&r.sin_addr.s_addr,&l.sin_addr.s_addr, sizeof(r.sin_addr.s_addr))==0)&&
				(memcmp(&r.sin_port,&l.sin_port, sizeof(r.sin_port))==0)&&
				(memcmp(&rl.sin_addr.s_addr,&ll.sin_addr.s_addr,sizeof(rl.sin_addr.s_addr))==0)&&
				(memcmp(&rl.sin_port,&ll.sin_port,sizeof(rl.sin_port))==0)) {
				peer->v4Path.lr = now;
				pathAlreadyKnown = true;
			}
		} else if((path->addr.address.ss_family == AF_INET6)&&(peer->v6Path.p)) {
			struct sockaddr_in6 r;
			memcpy(&r, (struct sockaddr_in6 *)(&path->addr), sizeof(r));
			struct sockaddr_in6 l;
			memcpy(&l, (struct sockaddr_in6 *)(&peer->v6Path.p->addr), sizeof(l));
			struct sockaddr_in6 rl;
			memcpy(&rl, (struct sockaddr_in6 *)(&path->localAddress), sizeof(rl));
			struct sockaddr_in6 ll;
			memcpy(&ll, (struct sockaddr_in6 *)(&peer->v6Path.p->localAddress), sizeof(ll));
			if ((memcmp(&r.sin6_addr.s6_addr,&l.sin6_addr.s6_addr, sizeof(r.sin6_addr.s6_addr))==0)&&
				(memcmp(&r.sin6_port,&l.sin6_port, sizeof(r.sin6_port))==0)&&
				(memcmp(&rl.sin6_addr.s6_addr,&ll.sin6_addr.s6_addr,sizeof(rl.sin6_addr.s6_addr))==0)&&
				(memcmp(&rl.sin6_port,&ll.sin6_port,sizeof(rl.sin6_port))==0)) {
				peer->v6Path.lr = now;
				pathAlreadyKnown = true;
			}			
		}
		if (!pathAlreadyKnown) {
			PeerPath *potentialNewPeerPath = (PeerPath *)0;
			if (path->addr.address.ss_family == AF_INET) {
				if ((!peer->v4Path.p) || (!Path_Alive(peer->v4Path.p, now))) {
					potentialNewPeerPath = &peer->v4Path;
				}
			} else if (path->addr.address.ss_family == AF_INET6) {
				if ((!peer->v6Path.p) || (!Path_Alive(peer->v6Path.p, now))) {
					potentialNewPeerPath = &peer->v6Path;
				}
			}
			if (potentialNewPeerPath) {
				if (verb == VERB_OK) {
					potentialNewPeerPath->lr = now;
					potentialNewPeerPath->p = path;
				} else {
					printf("got %s via unknown path %s(%s), confirming...\n",verbString(verb),Address_ToString(peer->id._address),InetAddress_toString(&path->addr));
					attemptToContactAt(peer,&path->localAddress,&path->addr,now,true,nextOutgoingCounter(path));
					path->lastOut = now;
				}
			}
		}

	}else if(Peer_TrustEstablished(peer,now)){
		//need to do 
	}
		

}



