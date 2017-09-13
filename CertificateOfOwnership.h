#ifndef ZT_CERTIFICATEOFOWNERSHIP_H
#define ZT_CERTIFICATEOFOWNERSHIP_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Constants.h"
#include "C25519.h"
#include "Address.h"
#include "Identity.h"
#include "Buffer.h"
#include "InetAddress.h"

// Max things per CertificateOfOwnership
#define ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS 16

// Maximum size of a thing's value field in bytes
#define ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE 16

enum Thing
{
	THING_NULL = 0,
	THING_MAC_ADDRESS = 1,
	THING_IPV4_ADDRESS = 2,
	THING_IPV6_ADDRESS = 3
};

typedef struct{
	uint64_t networkId;
	uint64_t ts;
	uint64_t flags;
	uint32_t id;
	uint16_t thingCount;
	uint8_t thingTypes[ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS];
	uint8_t thingValues[ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS][ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE];
	Address issuedTo;
	Address signedBy;
	Signature signature;
}CertificateOfOwnership;

void CertificateOfOwnership_serialize(CertificateOfOwnership *coo, Buffer *buf,const bool forSign);
unsigned int CertificateOfOwnership_deserialize(Buffer *buf, unsigned int startAt, CertificateOfOwnership *coo);
bool CertificateOfOwnership_sign(const Identity *signer, CertificateOfOwnership *coo);
void CertificateOfOwnership_init(CertificateOfOwnership *coo,const uint64_t nwid,const uint64_t ts,const Address issuedTo,const uint32_t id);
void CertificateOfOwnership_addThingIp(CertificateOfOwnership *coo,const InetAddress *ip);

#endif
