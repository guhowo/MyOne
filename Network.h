#ifndef _ZT_NETWORK_H
#define _ZT_NETWORK_H

#include "ZeroTierOne.h"
#include "CertificateOfMembership.h"
#include "NetworkConfig.h"
#include "Address.h"
#include "Buffer.h"
#include "avl_local.h"
#include "Peer.h"
#include "MulticastGroup.h"
#include "MAC.h"

enum AddCredentialResult
{
    ADD_REJECTED,
    ADD_ACCEPTED_NEW,
    ADD_ACCEPTED_REDUNDANT,
    ADD_DEFERRED_FOR_WHOIS
};

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

//controller structure
typedef struct _Networks{
    struct list_head list;
    uint64_t nwid;
    //json_object network;
    NetworkInfo network;
    TREE *member;
}Networks;

Networks *Network_findNetwork(uint64_t nwid);
uint64_t Network_handleConfigChunk(NetworkInfo *nwInfo,const uint64_t packetId,const Address source,const Buffer *chunk,unsigned int ptr);
bool Network_gate(NetworkInfo *network, const Peer *peer);
bool Network_subscribedToMulticastGroup(NetworkInfo *network,const MulticastGroup *mg,bool includeBridgedGroups);
void Networks_init(void);
enum AddCredentialResult Network_addCredential(NetworkInfo *nw,CertificateOfMembership *com);

#endif
