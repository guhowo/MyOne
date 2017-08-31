#ifndef _CERTIFICATEOFMEMBERSHIP_H
#define _CERTIFICATEOFMEMBERSHIP_H

#include "Buffer.h"
#include "C25519.h"
#include "Address.h"
#include "Identity.h"

#define ZT_NETWORK_COM_MAX_QUALIFIERS 8

typedef struct _Qualifier{
	uint64_t id;
	uint64_t value;
	uint64_t maxDelta;
}Qualifier;

typedef struct{
	Address _signedBy;
	Qualifier _qualifiers[ZT_NETWORK_COM_MAX_QUALIFIERS];
	unsigned int _qualifierCount;
	Signature _signature;
}CertificateOfMembership;

CertificateOfMembership * CertificateOfMembership_init(void);
bool CertificateOfMembership_sign(const Identity *with, CertificateOfMembership *com);
void CertificateOfMembership_serialize(Buffer *b, CertificateOfMembership *com);
unsigned int CertificateOfMembership_deserialize(Buffer *b, unsigned int startAt, CertificateOfMembership *com);

#endif
