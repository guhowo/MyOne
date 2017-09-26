#include "Network.h"

Networks netWorks;

void Networks_init(void)
{
    INIT_LIST_HEAD(&netWorks.list);
    return;
}

Networks *Network_findNetwork(uint64_t nwid)
{
    Networks *tmp;
    list_for_each_entry(tmp, &netWorks.list, list) {
        if(tmp->nwid == nwid)
            return tmp;
    }
    return NULL;

}

uint64_t Network_handleConfigChunk(NetworkInfo *nwInfo,const uint64_t packetId,const Address source,const Buffer *chunk,unsigned int ptr)
{
    if(nwInfo->destroyed)
        return 0;

    return 0;
}

bool Network_gate(NetworkInfo       *network, const Peer *peer)
{
    return false;
}

bool Network_subscribedToMulticastGroup(NetworkInfo *network,const MulticastGroup *mg,bool includeBridgedGroups)
{
    return false;
}

enum AddCredentialResult Network_addCredential(NetworkInfo *nw,CertificateOfMembership *com)
{
    return ADD_REJECTED;
}


