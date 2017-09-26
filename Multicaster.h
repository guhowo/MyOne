#ifndef _MULTICASTER_H_
#define _MULTICASTER_H_

#include "list.h"
#include "Network.h"
#include "MulticastGroup.h"
#include "MAC.h"

typedef struct _GatherAuthKey
{
    uint64_t member;
    uint64_t networkId;
}GatherAuthKey;

static inline bool GatherAuthKey_isEql(GatherAuthKey *ga, GatherAuthKey *gb)
{
    return ((ga->member == gb->member)&&(ga->networkId == gb->networkId));
}

typedef struct{
    uint64_t nwid;
    MulticastGroup mg;
}McKey;
    
static inline bool McKey_isEql(McKey *ma, McKey *mb)
{
    return ((ma->nwid == mb->nwid)&&(ma->mg._adi == mb->mg._adi)&&(ma->mg._mac == mb->mg._mac));
}

typedef struct{
    Address address;
    uint64_t timestamp; // time of last notification
}MulticastGroupMember;

typedef struct{
    uint64_t lastExplicitGather;
//    std::list<OutboundMulticast> txQueue; // pending outbound multicasts
    Address alreadySentTo[256];
    int alreadySentToNum;
    MulticastGroupMember members[256]; // members of this group
    int membersNum;
}MulticastGroupStatus;

typedef struct{
    struct list_head list;
    McKey Key;
    MulticastGroupStatus gs;
}GroupList; 

typedef struct{
    struct list_head list;
    GatherAuthKey Key;
    uint64_t ga;
}GatherAuthList;

typedef struct{
    GroupList groups;
    GatherAuthList gatherAuth;
}Multicaster;


void Multicaster_init(void);
void Multicaster_addMultiple(uint64_t now, uint64_t nwid, const MulticastGroup *mg, const void *addresses, unsigned int count, unsigned int totalKnown);
void Multicaster_remove(uint64_t nwid,const MulticastGroup *mg,const Address *member);
bool Multicaster_cacheAuthorized(Address a, uint64_t nwid, uint64_t now);
void Multicaster_add(uint64_t now, uint64_t nwid, const MulticastGroup *mg, Address member);
void Multicaster_addCredential(CertificateOfMembership *com,bool alreadyValidated);
unsigned int Multicaster_gather(const Address queryingPeer,uint64_t nwid,const MulticastGroup *mg,Buffer *appendTo,unsigned int limit);

#endif
