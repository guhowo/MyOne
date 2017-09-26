#ifndef _ZT_NETWORK_CONFIG_H
#define _ZT_NETWORK_CONFIG_H

#include "ZeroTierOne.h"
#include "Utils.h"
#include "Dictionary.h"
#include "Capability.h"
#include "Tag.h"
#include "CertificateOfOwnership.h"
#include "CertificateOfMembership.h"

#define ZT_NETWORK_MAX_INCOMING_UPDATES 3
#define ZT_NETWORKCONFIG_DICT_CAPACITY    (1024 + (sizeof(ZT_VirtualNetworkRule) * ZT_MAX_NETWORK_RULES) + (sizeof(Capability) * ZT_MAX_NETWORK_CAPABILITIES) + (sizeof(Tag) * ZT_MAX_NETWORK_TAGS) + (sizeof(CertificateOfOwnership) * ZT_MAX_CERTIFICATES_OF_OWNERSHIP))
#define ZT_NETWORK_MAX_UPDATE_CHUNKS ((ZT_NETWORKCONFIG_DICT_CAPACITY / 1024) + 1)

enum ncFailure{
    NETCONF_FAILURE_NONE,
    NETCONF_FAILURE_ACCESS_DENIED,
    NETCONF_FAILURE_NOT_FOUND,
    NETCONF_FAILURE_INIT_FAILED
};

typedef struct _NetworkConfig{
    /**
     * Network ID that this configuration applies to
     */
    uint64_t networkId;

    /**
     * Controller-side time of config generation/issue
     */
    uint64_t timestamp;

    /**
     * Max difference between timestamp and tag/capability timestamp
     */
    uint64_t credentialTimeMaxDelta;

    /**
     * Controller-side revision counter for this configuration
     */
    uint64_t revision;

    /**
     * Address of device to which this config is issued
     */
    Address issuedTo;

    /**
     * Flags (64-bit)
     */
    uint64_t flags;

    /**
     * Network MTU
     */
    unsigned int mtu;

    /**
     * Maximum number of recipients per multicast (not including active bridges)
     */
    unsigned int multicastLimit;

    /**
     * Number of specialists
     */
    unsigned int specialistCount;

    /**
     * Number of routes
     */
    unsigned int routeCount;

    /**
     * Number of ZT-managed static IP assignments
     */
    unsigned int staticIpCount;

    /**
     * Number of rule table entries
     */
    unsigned int ruleCount;

    /**
     * Number of capabilities
     */
    unsigned int capabilityCount;

    /**
     * Number of tags
     */
    unsigned int tagCount;

    /**
     * Number of certificates of ownership
     */
    unsigned int certificateOfOwnershipCount;

    /**
     * Specialist devices
     *
     * For each entry the least significant 40 bits are the device's ZeroTier
     * address and the most significant 24 bits are flags indicating its role.
     */
    uint64_t specialists[ZT_MAX_NETWORK_SPECIALISTS];

    /**
     * Statically defined "pushed" routes (including default gateways)
     */
    ZT_VirtualNetworkRoute routes[ZT_MAX_NETWORK_ROUTES];

    /**
     * Static IP assignments
     */
    InetAddress staticIps[ZT_MAX_ZT_ASSIGNED_ADDRESSES];

    /**
     * Base network rules
     */
    ZT_VirtualNetworkRule rules[ZT_MAX_NETWORK_RULES];

    /**
     * Capabilities for this node on this network, in ascending order of capability ID
     */
    Capability capabilities[ZT_MAX_NETWORK_CAPABILITIES];

    /**
     * Tags for this node on this network, in ascending order of tag ID
     */
    Tag tags[ZT_MAX_NETWORK_TAGS];

    /**
     * Certificates of ownership for this network member
     */
    CertificateOfOwnership certificatesOfOwnership[ZT_MAX_CERTIFICATES_OF_OWNERSHIP];

    /**
     * Network type (currently just public or private)
     */
    enum ZT_VirtualNetworkType type;

    /**
     * Network short name or empty string if not defined
     */
    char name[ZT_MAX_NETWORK_SHORT_NAME_LENGTH + 1];

    /**
     * Certficiate of membership (for private networks)
     */
    CertificateOfMembership com;

}NetworkConfig;

bool toDictionary(Dictionary *d, NetworkConfig *nc);
bool fromDictionary(Dictionary *d, NetworkConfig *nc);

#endif

