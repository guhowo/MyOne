#include <stdio.h>
#include <malloc.h>

#include "Switch.h"
#include "ZeroTierOne.h"
#include "Packet.h"
#include "IncomingPacket.h"
#include "Identity.h"

static outstandingWhoisRequests WhoisRequests;
static LastUniteAttempt lastUniteAttempt;
extern RuntimeEnvironment *RR;

void Switch_Init()
{
    INIT_LIST_HEAD(&(WhoisRequests.list));
    INIT_LIST_HEAD(&(lastUniteAttempt.list));
    return;
}

bool Switch_send(Buffer *packet, bool encrypt)
{
    Address destination;
    Address_SetTo(packet->b+8,ZT_ADDRESS_LENGTH,&destination);

    if(destination == RR->identity._address) {
        printf("BUG: caught attempt to send() to self, ignored\n");
        return true;
    }

    return Switch_trySend(packet,encrypt);
}


WhoisRequest *_findWhois(const Address addr)
{
    outstandingWhoisRequests *tmp;
    
    list_for_each_entry(tmp, &(WhoisRequests.list), list) {
        if(tmp->addr == addr)
            return &(tmp->whoisReq);
    }
    return NULL;
}

bool _sendWhoisRequest(const Address addr,const Address *peersAlreadyConsulted,unsigned int numPeersAlreadyConsulted)
{
    Peer *upstream=Topology_getUpstreamPeer(peersAlreadyConsulted,numPeersAlreadyConsulted,false);
    
    if (upstream) {
        Buffer outp;
        Buffer_Init(&outp);
        Packet(&outp,upstream->id._address,RR->identity._address,VERB_WHOIS);
        Address_AppendTo(&outp,addr);
        uint64_t packetId=Utils_ntoh_u64(*(uint64_t *)&(outp.b[0]));
        expectReplyTo(packetId);
        char * p = Address_ToString(upstream->id._address);
        char * q = Address_ToString(addr);
        printf("_sendWhoisRequest to upstream %s to ask WHOIS %s \n", p, q);
        free(p);
        free(q);
        return Switch_send(&outp,true);
    }
    
    return false;
}

void Switch_requestWhois(const Address addr)
{
    bool inserted = false;

    WhoisRequest *r = _findWhois(addr);
    if(!r) {
        outstandingWhoisRequests *tmp=(outstandingWhoisRequests *)malloc(sizeof(outstandingWhoisRequests));
        tmp->whoisReq.lastSent = RR->now;
        tmp->whoisReq.retries = 0;
        tmp->addr = addr;
        list_add_tail(&tmp->list,&WhoisRequests.list);
        inserted = true;
    } else {
        r->retries = 0; // reset retry count if entry already existed, but keep waiting and retry again after normal timeout
    }
    
    if (inserted){
        char * p = Address_ToString(addr);
        printf("Switch_requestWhois : whois address = %s\n", p);
        free(p);
        
        _sendWhoisRequest(addr,(const Address *)0,0);
    }
}

unsigned long Switch_doTimerTasks(uint64_t now)
{
    unsigned long nextDelay = 0xffffffff; // ceiling delay, caller will cap to minimum

    struct list_head *pos,*n;
    list_for_each_safe(pos,n,&WhoisRequests.list) {
        outstandingWhoisRequests *tmp=(outstandingWhoisRequests *)pos;
        const unsigned long since = (unsigned long)(now - tmp->whoisReq.lastSent);
        if (since >= ZT_WHOIS_RETRY_DELAY) {
            if (tmp->whoisReq.retries >= ZT_MAX_WHOIS_RETRIES) {
                char * p = Address_ToString(tmp->addr);
                printf("WHOIS %s timed out\n", p);
                free(p);
                
                list_del(&tmp->list);
                free(tmp);
            } else {
                char * p = Address_ToString(tmp->addr);
                printf("Switch_doTimerTasks : whois address = %s, retries = %d, pos=%x \n", p, tmp->whoisReq.retries, tmp);
                tmp->whoisReq.lastSent = now;
                bool flag=_sendWhoisRequest(tmp->addr,tmp->whoisReq.peersConsulted,(tmp->whoisReq.retries > 1) ? tmp->whoisReq.retries : 0);
                if(flag) {
                    list_del(&tmp->list);
                    free(tmp);
                } 
                printf("WHOIS %s (retry %u)\n", p, tmp->whoisReq.retries);
                free(p);
                ++tmp->whoisReq.retries;
                nextDelay = MIN(nextDelay,(unsigned long)ZT_WHOIS_RETRY_DELAY);
            }
        } else {
            nextDelay = MIN(nextDelay,ZT_WHOIS_RETRY_DELAY - since);
        }
    }
    
    // Remove really old last unite attempt entries to keep table size controlled
    struct list_head *p,*q;
    list_for_each_safe(p,q,&lastUniteAttempt.list) {
        LastUniteAttempt *tmp=(LastUniteAttempt *)p;
        if((now-tmp->ts) >= (ZT_MIN_UNITE_INTERVAL * 8)) {
            char *p = Address_ToString(tmp->big);
            char *q = Address_ToString(tmp->little);
            printf("Last unite attempt timed oute,between %s and %s \n", p, q);
            free(p);
            free(q);
            
            list_del(&tmp->list);
            free(tmp);
        }
    }
    
    return nextDelay;
}


bool Switch_trySend(Buffer *buf, bool encrypt)
{
    unsigned char *data=buf->b;
    unsigned int len=buf->len;
    Path *viaPath=NULL;
    const uint64_t _now = RR->now;
    Address destination;
    memset(&destination,0,sizeof(destination));
    Address_SetTo(data+ZT_PACKET_IDX_DEST,ZT_ADDRESS_LENGTH,&destination);
    
    Peer* peer=Peer_GotByAddress(destination);
    if (peer) {
        /* First get the best path, and if it's dead (and this is not a root)
         * we attempt to re-activate that path but this packet will flow
         * upstream. If the path comes back alive, it will be used in the future.
         * For roots we don't do the alive check since roots are not required
         * to send heartbeats "down" and because we have to at least try to
         * go somewhere. */

        viaPath = peer->v4Path.p;
        if ( (viaPath) && (!Path_Alive(viaPath,_now)) && (!Topology_IsInUpstreams(&peer->id._address)) ) {
            if ((_now - viaPath->lastOut) > MAX((_now - viaPath->lastIn) * 4,(uint64_t)ZT_PATH_MIN_REACTIVATE_INTERVAL)) {
                attemptToContactAt(peer,&viaPath->localAddress,&viaPath->addr,_now,false,nextOutgoingCounter(viaPath));
                viaPath->lastOut = _now;
            }

            viaPath=NULL;
        }

        if (!viaPath) {
            return false;
        }
    } else {
        //printf("Switch_trySend : whois address = %s\n",Address_ToString(destination));
        Switch_requestWhois(destination);    
        return false;
    }
    
    Packet_Armor(buf, peer->key,encrypt,nextOutgoingCounter(viaPath));
    Path_Send(viaPath,buf,_now);
    
    return true;

}

LastUniteAttempt *_findLastUniteAttempt(Address src,Address dest)
{
    Address big = src>dest?src:dest;
    Address little = src<dest?src:dest;

    LastUniteAttempt *tmp;
    list_for_each_entry(tmp,&lastUniteAttempt.list,list) {
        if((tmp->big==big)&&(tmp->little==little))
            return tmp;
    }

    return NULL;
}

bool Switch_shouldUnite(const uint64_t now,const Address source,const Address destination)
{
    LastUniteAttempt *r=_findLastUniteAttempt(source,destination);
    if(!r) {
        r=(LastUniteAttempt *)malloc(sizeof(LastUniteAttempt));
        r->big = source>destination?source:destination;
        r->little = source>destination?destination:source;
        r->ts = now;
        list_add_tail(&r->list,&lastUniteAttempt.list);
    }

    if((now - r->ts) >= ZT_MIN_UNITE_INTERVAL) {
        r->ts = now;
        return true;
    }

    return false;
}


void Switch_doAnythingWaitingForPeer(Peer *peer)
{
    // cancel pending WHOIS since we now know this peer
    struct list_head *pos,*n;
    list_for_each_safe(pos,n,&WhoisRequests.list) {
        outstandingWhoisRequests *tmp=(outstandingWhoisRequests *)pos;
        if(tmp->addr==peer->id._address) {
            Peer *upstream=Topology_getUpstreamPeer((const Address *)0,0,false);
            if (upstream) {
                Buffer outp;
                Buffer_Init(&outp);
                Packet(&outp,upstream->id._address,RR->identity._address,VERB_WHOIS);
                Address_AppendTo(&outp,peer->id._address);
                uint64_t packetId=Utils_ntoh_u64(*(uint64_t *)&(outp.b[0]));
                expectReplyTo(packetId);
                char *p = Address_ToString(upstream->id._address);
                char *q = Address_ToString(peer->id._address);
                printf("_sendWhoisRequest to upstream %s to ask WHOIS %s in doAnythingWaitingForPeer\n", p, q);
                free(p);
                free(q);
                
                if(Switch_trySend(&outp,true)) {
                    list_del(&tmp->list);
                    free(tmp);
                }
            }
        }
    }
/*+++++++++++++++++++need to do +++++++++++++++++*/    
    
}

