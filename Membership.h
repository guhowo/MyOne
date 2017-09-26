#ifndef _MEMBERSHIP_H_
#define _MEMBERSHIP_H_

enum AddCredentialResult
{
    ADD_REJECTED,
    ADD_ACCEPTED_NEW,
    ADD_ACCEPTED_REDUNDANT,
    ADD_DEFERRED_FOR_WHOIS
};

typedef struct {
    // Last time we pushed MULTICAST_LIKE(s)
    uint64_t _lastUpdatedMulticast;

    // Last time we pushed our COM to this peer
    uint64_t _lastPushedCom;

    // Revocation threshold for COM or 0 if none
    uint64_t _comRevocationThreshold;

    // Remote member's latest network COM
    CertificateOfMembership _com;

    // Revocations by credentialKey()
    Hashtable< uint64_t,uint64_t > _revocations;

    // Remote credentials that we have received from this member (and that are valid)
    Hashtable< uint32_t,Tag > _remoteTags;
    Hashtable< uint32_t,Capability > _remoteCaps;
    Hashtable< uint32_t,CertificateOfOwnership > _remoteCoos;
    // Time we last pushed our local credentials to this member
    struct {
        uint64_t tag[ZT_MAX_NETWORK_TAGS];
        uint64_t cap[ZT_MAX_NETWORK_CAPABILITIES];
        uint64_t coo[ZT_MAX_CERTIFICATES_OF_OWNERSHIP];
    } _localCredLastPushed;
}Membership;

#endif
