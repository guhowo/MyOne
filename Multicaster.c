#include "Multicaster.h"
#include "Address.h"
#include "CertificateOfMembership.h"
#include "RuntimeEnvironment.h"

static Multicaster mc;
extern RuntimeEnvironment *RR;

void Multicaster_init(void){
    INIT_LIST_HEAD(&mc.groups.list);
    INIT_LIST_HEAD(&mc.gatherAuth.list);
    
    RR->mc = &mc;
    return;
}

MulticastGroupStatus * mc_getMGS(McKey *key){
    GroupList *pos = NULL;
    MulticastGroupStatus * p = NULL;

    list_for_each_entry(pos, &mc.groups.list, list){
        if(McKey_isEql(&pos->Key, key)){
            p = &pos->gs;
            break;
        }
    }

    return p;
}

void multicaster_add(uint64_t now, uint64_t nwid, const MulticastGroup *mg, MulticastGroupStatus *gs, const Address member)
{
    int i;
    bool isAlreadySend = false;
    MulticastGroupMember *mm = gs->members;
 
	// Do not add self -- even if someone else returns it
	if (member == RR->identity._address){
		return;
    }
    if(gs->membersNum >= 256){
        printf("too manry members\n");
        return;
    }

    for(i = 0; i < gs->membersNum; i++){
        if(mm[i].address == member){
            mm[i].timestamp = now;
            return;
        }
    }
    mm[gs->membersNum].address = member;
    mm[gs->membersNum++].timestamp = now;

	printf("..MC %s joined multicast group %.16llx\n", Address_ToString(member), nwid);
    if(gs->alreadySentToNum == 256){
        gs->alreadySentToNum = 0;
        return;
    }

    for(i = 0; i < gs->alreadySentToNum; i++){
        if(gs->alreadySentTo[i] == member){
            isAlreadySend = true;
            break;
        }
    }

    if((!isAlreadySend)&&(gs->alreadySentToNum != 256)){
        gs->alreadySentTo[gs->alreadySentToNum++] = member;
        //sendOnly
        //no network donot send
    }
    return;
}


void Multicaster_addMultiple(uint64_t now, uint64_t nwid, const MulticastGroup *mg, 
                                        const void *addresses, unsigned int count, unsigned int totalKnown)
{
	const unsigned char *p = (const unsigned char *)addresses;
	const unsigned char *e = p + (5 * count);
    McKey mk;

    mk.nwid = nwid;
    memcpy(&mk.mg, mg, sizeof(MulticastGroup));
    
	MulticastGroupStatus *gs = mc_getMGS(&mk);
    if(!gs){
        GroupList *pg = malloc(sizeof(GroupList));
        memset(pg, 0, sizeof(GroupList));
        memcpy(&pg->Key, &mk, sizeof(McKey));
        list_add(&pg->list, &mc.groups.list);
        gs = &pg->gs;
    }
	while (p != e) {
        Address addr;
        Address_SetTo(p, 5, &addr);
		multicaster_add(now, nwid, mg, gs, addr);
		p += 5;
	}
}

void Multicaster_remove(uint64_t nwid,const MulticastGroup *mg,const Address *member)
{
    McKey mk;
    int i, j;

    mk.nwid = nwid;
    memcpy(&mk.mg, mg, sizeof(MulticastGroup));
    MulticastGroupStatus *s = mc_getMGS(&mk);
    if (s) {
        for(i = 0; i<s->membersNum; i++){
            if(s->members[i].address == member){
                break;
            }
        }
        if(i < s->membersNum){
            for(j = i; j < s->membersNum; j++){
                memcpy(&(s->members[j]), &(s->members[j+1]), sizeof(MulticastGroupMember));
            }
            s->membersNum--;
        }
    }

    return;
}

uint64_t *mc_getGA(GatherAuthKey *key){
    uint64_t *pga = NULL;
    GatherAuthList *pos = NULL;

    list_for_each_entry(pos, &mc.gatherAuth.list, list){
        if(GatherAuthKey_isEql(&pos->Key, key)){
            pga = &pos->ga;
            break;
        }
    }
    return pga;
}

void Multicaster_addCredential(CertificateOfMembership *com,bool alreadyValidated)
{
    GatherAuthKey key;
    uint64_t *pga = NULL;
    
    key.member = COM_issuedTo(com);
    key.networkId = COM_networkId(com);

	if ((alreadyValidated)||(CertificateOfMembership_verify(com) == 0)) {
        pga = mc_getGA(&key);
        if(pga){
            *pga = RR->now;
        }else{
            GatherAuthList *p = (GatherAuthList *)malloc(sizeof(GatherAuthList));
            memcpy(&p->Key, &key, sizeof(GatherAuthKey));
            p->ga = RR->now;
            list_add(&p->list, &mc.gatherAuth.list);
        }
	}
}

bool Multicaster_cacheAuthorized(Address a, uint64_t nwid, uint64_t now)
{    
    GatherAuthKey key;
    
    key.member = a;
    key.networkId = nwid;
    
    const uint64_t *p = mc_getGA(&key);
    return ((p)&&((now - *p) < ZT_MULTICAST_CREDENTIAL_EXPIRATON));
}

void Multicaster_add(uint64_t now, uint64_t nwid, const MulticastGroup *mg, Address member)
{
    McKey key;
    MulticastGroupStatus *gs = NULL;

    key.nwid = nwid;
    memcpy(&key.mg, mg, sizeof(MulticastGroup));

    gs = mc_getMGS(&key);
    if(!gs){
        GroupList *pg = malloc(sizeof(GroupList));
        memset(pg, 0, sizeof(GroupList));
        memcpy(&pg->Key, &key, sizeof(McKey));
        list_add(&pg->list, &mc.groups.list);
        gs = &pg->gs;
    }
    multicaster_add(now, nwid, mg, gs, member);
}

