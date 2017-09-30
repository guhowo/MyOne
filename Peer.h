#ifndef _ZT_PEER_H
#define _ZT_PEER_H

#include "Identity.h"
#include "Path.h"

typedef struct _PeerPath{
    uint64_t lr; // time of last valid ZeroTier packet
    Path* p;
}PeerPath;

typedef struct _Peer{
    /*
    const RuntimeEnvironment *RR;

    InetAddress _v4ClusterPreferred;
    InetAddress _v6ClusterPreferred;

    Mutex _paths_m;


    AtomicCounter __refCount;
    */
    uint8_t key[ZT_PEER_SECRET_KEY_LENGTH];

    uint64_t lastReceive;
    uint64_t lastNontrivialReceive; 
    uint64_t lastTriedMemorizedPath;
    uint64_t lastDirectPathPushSent;
    uint64_t lastDirectPathPushReceive;
    uint64_t lastCredentialRequestSent;
    uint64_t lastWhoisRequestReceived;
    uint64_t lastEchoRequestReceived;
    uint64_t lastComRequestReceived;
    uint64_t lastComRequestSent;
    uint64_t lastCredentialsReceived;
    uint64_t lastTrustEstablishedPacketReceived;

    PeerPath v4Path; // IPv4 direct path
    PeerPath v6Path; // IPv6 direct path

    Identity id;
    unsigned int latency;
    uint16_t vProto;
    uint16_t vMajor;
    uint16_t vMinor;
    uint16_t vRevision;    
    unsigned int directPathPushCutoffCount;
    unsigned int credentialsCutoffCount;
}Peer;

void Peer_Init(Peer *p, Identity *peerId);
Peer *Peer_GotByAddress(Address addr);
void setRemoteVersion(Peer *peer,unsigned int vproto,unsigned int vmaj,unsigned int vmin,unsigned int vrev);
void received(Peer *peer,    Path *path,const unsigned int hops,const uint64_t packetId,const enum Verb verb,const uint64_t inRePacketId,const enum Verb inReVerb,const bool trustEstablished);
void attemptToContactAt(Peer *peer,InetAddress *localAddr,InetAddress *atAddress,uint64_t _now,bool sendFullHello,unsigned int counter);
void Peer_tryMemorizedPath(Peer *peer,uint64_t now);
bool Peer_rateGateOutgoingComRequest(Peer *peer,const uint64_t _now);
bool Peer_rateGateInboundWhoisRequest(Peer *peer,const uint64_t _now);
bool Peer_rateGateEchoRequest(Peer *peer,const uint64_t now);
bool Peer_TrustEstablished(Peer *peer,const uint64_t _now);
bool Peer_sendDirect(Peer *peer,Buffer *buf,uint64_t now,bool force);
void Peer_getRendezvousAddresses(Peer *peer,uint64_t now,InetAddress *v4,InetAddress *v6);
bool Peer_hasActivePathTo(Peer *peer, uint64_t now,const InetAddress *addr);
void Peer_setClusterPreferred(Peer * peer, const InetAddress *addr);
bool Peer_rateGateCredentialsReceived(Peer *peer,uint64_t now);
bool Peer_isAlive(const Peer *peer);

#endif

