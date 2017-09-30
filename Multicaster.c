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
        printf("too many members\n");
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
    char * p = Address_ToString(member);
    printf("..MC %s joined multicast group %.16llx\n", p, nwid);
    free(p);
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
    int i, j, mn;

    mk.nwid = nwid;
    memcpy(&mk.mg, mg, sizeof(MulticastGroup));
    MulticastGroupStatus *s = mc_getMGS(&mk);
    if (s) {
        mn = s->membersNum;
        for(i = 0; i< mn; i++){
            if(s->members[i].address == *member){
                break;
            }
        }
        if(i < mn){
            for(j = i; j < mn - 1; j++){
                memcpy(&(s->members[j]), &(s->members[j+1]), sizeof(MulticastGroupMember));
            }
            s->membersNum--;
        }
    }

    return;
}

uint64_t *mc_getGA(GatherAuthKey *key)
{
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


unsigned int Multicaster_gather(const Address queryingPeer,uint64_t nwid,const MulticastGroup *mg,Buffer *appendTo,unsigned int limit)
{
    unsigned char *p;
    unsigned int added = 0,i,k,rptr,totalKnown = 0;
    uint64_t a,picked[(ZT_PROTO_MAX_PACKET_LENGTH / 5) + 2];
    McKey key;
    key.mg._adi=mg->_adi;
    key.mg._mac=mg->_mac;
    key.nwid=nwid;

    if (!limit)
        return 0;
    else if (limit > 0xffff)
        limit = 0xffff;

    const unsigned int totalAt = appendTo->len;
    appendTo->len += 4;  // sizeof(uint32_t)
    const unsigned int addedAt = appendTo->len;
    appendTo->len += 2; // sizeof(uint16_t)

    // Return myself if I am a member of this group
    Networks *nw=Network_findNetwork(nwid);
    if(nw && Network_subscribedToMulticastGroup(&nw->network,mg,true)) {
        Address_AppendTo(appendTo,RR->identity._address);
        ++totalKnown;
        ++added;
    }

    const MulticastGroupStatus *s = mc_getMGS(&key);
    if ((s)&&(s->membersNum!=0)) {
        printf("s->membersNum = %d\n",s->membersNum);
        totalKnown += (unsigned int)s->membersNum;

        // Members are returned in random order so that repeated gather queries
        // will return different subsets of a large multicast group.
        k = 0;
        while ((added < limit)&&(k < s->membersNum)&&((appendTo->len + ZT_ADDRESS_LENGTH) <= ZT_UDP_DEFAULT_PAYLOAD_MTU)) {
            rptr = (unsigned int)prng();

restart_member_scan:
            a = s->members[rptr % (unsigned int)s->membersNum].address;
            for(i=0;i<k;++i) {
                if (picked[i] == a) {
                    ++rptr;
                    goto restart_member_scan;
                }
            }
            picked[k++] = a;

            if (queryingPeer != a) { // do not return the peer that is making the request as a result
                p = appendTo->b + appendTo->len;
                appendTo->len +=  ZT_ADDRESS_LENGTH;
                *(p++) = (unsigned char)((a >> 32) & 0xff);
                *(p++) = (unsigned char)((a >> 24) & 0xff);
                *(p++) = (unsigned char)((a >> 16) & 0xff);
                *(p++) = (unsigned char)((a >> 8) & 0xff);
                *p = (unsigned char)(a & 0xff);
                ++added;
            }
        }
    }

    setAt(appendTo,totalAt,(uint32_t)totalKnown);
    setAt(appendTo,addedAt,(uint16_t)added);

    return added;
}

void Multicaster_clean(void)
{
    GroupList *gp=&(mc.groups);
    GatherAuthList *ga=&(mc.gatherAuth);

    //flush groups
    struct list_head *pos,*n;
    list_for_each_safe(pos,n,&gp->list) {
        GroupList *tmp=(GroupList *)pos;
        unsigned int i=0;
        while(i<tmp->gs.membersNum) {
            const unsigned long since = (unsigned long)(RR->now - tmp->gs.members[i].timestamp);
            if(since > ZT_MULTICAST_LIKE_EXPIRE) {
                printf("Multicaster_remove a member, address = %s\n",Address_ToString(tmp->gs.members[i].address));
                Multicaster_remove(tmp->Key.nwid,&(tmp->Key.mg),&(tmp->gs.members[i].address));
            }
            else
                i++;
        }
        
        if(tmp->gs.membersNum == 0) {   //no member in this node
            list_del(&tmp->list);
            free(tmp);
        }
    }

    //flush gatherAuth
    list_for_each_safe(pos,n,&ga->list) {
        GatherAuthList *tmp=(GatherAuthList *)pos;
        const unsigned long since = (unsigned long)(RR->now - tmp->ga);
        if(since > ZT_MULTICAST_CREDENTIAL_EXPIRATON) {
            list_del(&tmp->list);
            free(tmp);
        }
    }
    
}

