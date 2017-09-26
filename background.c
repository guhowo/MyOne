#include <stdio.h>
#include "background.h"
#include "Utils.h"
#include "Packet.h"
#include "InetAddress.h"
#include "Topology.h"
#include "World.h"
#include "Identity.h"
#include "Utils.h"
#include "list.h"
#include "RuntimeEnvironment.h"
#include "Switch.h"
#include "Constants.h"

static uint64_t lastPingCheck = 0;
extern RuntimeEnvironment *RR;

enum ZT_ResultCode processBackgroundTasks(void *tptr,uint64_t _now,volatile uint64_t *nextBackgroundTaskDeadline)
{
    unsigned long timeUntilNextPingCheck = ZT_PING_CHECK_INVERVAL;
    const uint64_t timeSinceLastPingCheck = _now - lastPingCheck;
    PeerNode *peerNode = NULL;
    InetAddress localInetAddr;
    InetAddrList *tmpInet = NULL;
    upstreamAddress *pUpStream = NULL;
    
    if (timeSinceLastPingCheck >= ZT_PING_CHECK_INVERVAL) {    
        lastPingCheck = now();

        //sendUpdatesToMembers(tptr);
        //requestConfiguration(tptr);

        // Do pings and keepalives
        memset(&localInetAddr,0,sizeof(InetAddress));
        list_for_each_entry(pUpStream, &(RR->pTopology->upstreamAddresses.list), list){
            peerNode = Topology_GetPeerNode(pUpStream->addr);
            if(!peerNode){
                continue;
            }
            list_for_each_entry(tmpInet, &(peerNode->pInetAddress->list), list){
                sendHELLO(&(peerNode->peer),&localInetAddr,&tmpInet->InetAddr,_now,0);
            }
        }
        // Run WHOIS to create Peer for any upstreams we could not contact (including pending moon seeds)
        // WHOIS works only in controller, not in Planet
        
    }else {
        timeUntilNextPingCheck -= (unsigned long)timeSinceLastPingCheck;
    }

    *nextBackgroundTaskDeadline = _now +MAX(MIN(timeUntilNextPingCheck,Switch_doTimerTasks(_now)),(unsigned long)ZT_CORE_TIMER_TASK_GRANULARITY);
    
    return ZT_RESULT_OK;
}


