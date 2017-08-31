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

// Max things per CertificateOfOwnership
#define ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS 16

// Maximum size of a thing's value field in bytes
#define ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE 16

typedef struct{
	uint64_t _networkId;
	uint64_t _ts;
	uint64_t _flags;
	uint32_t _id;
	uint16_t _thingCount;
	uint8_t _thingTypes[ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS];
	uint8_t _thingValues[ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS][ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE];
	Address _issuedTo;
	Address _signedBy;
	Signature _signature;
}CertificateOfOwnership;

void CertificateOfOwnership_serialize(CertificateOfOwnership *coo, Buffer *buf,const bool forSign);
unsigned int CertificateOfOwnership_deserialize(Buffer *buf, unsigned int startAt, CertificateOfOwnership *coo);
bool CertificateOfOwnership_sign(const Identity *signer, CertificateOfOwnership *coo);

#endif
