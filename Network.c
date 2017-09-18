#include "Network.h"

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
/*	const uint64_t now = RR->now;

	if (network->config.networkId != 0) {
		Membership *m = _memberships.get(peer->address());
		if ( (_config.isPublic()) || ((m)&&(m->isAllowedOnNetwork(_config))) ) {
			if (!m)
				m = &(_membership(peer->address()));
			if (m->multicastLikeGate(now)) {
				m->pushCredentials(RR,tPtr,now,peer->address(),_config,-1,false);
				_announceMulticastGroupsTo(tPtr,peer->address(),_allMulticastGroups());
			}
			return true;
		}
	}
*/    
	return false;
}

MAC MAC_setTo(const void *bits,unsigned int len)
{
    MAC m;
    
    if (len < 6) {
        return 0;
    }
    const unsigned char *b = (const unsigned char *)bits;
    m =  ((((uint64_t)*b) & 0xff) << 40); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 32); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 24); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 16); ++b;
    m |= ((((uint64_t)*b) & 0xff) << 8); ++b;
    m |= (((uint64_t)*b) & 0xff);
    return m;
}

enum AddCredentialResult Network_addCredential(NetworkInfo *nw,CertificateOfMembership *com)
{
    return ADD_REJECTED;
}

