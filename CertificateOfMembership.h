#ifndef _CERTIFICATEOFMEMBERSHIP_H
#define _CERTIFICATEOFMEMBERSHIP_H

#include "Buffer.h"
#include "C25519.h"
#include "Address.h"
#include "Identity.h"

#define ZT_NETWORK_COM_MAX_QUALIFIERS 8

enum ReservedId
{
	/**
	 * Timestamp of certificate
	 */
	COM_RESERVED_ID_TIMESTAMP = 0,

	/**
	 * Network ID for which certificate was issued
	 */
	COM_RESERVED_ID_NETWORK_ID = 1,

	/**
	 * ZeroTier address to whom certificate was issued
	 */
	COM_RESERVED_ID_ISSUED_TO = 2
};

typedef struct _Qualifier{
	uint64_t id;
	uint64_t value;
	uint64_t maxDelta;
}Qualifier;

typedef struct{
	Address signedBy;
	Qualifier qualifiers[ZT_NETWORK_COM_MAX_QUALIFIERS];
	unsigned int qualifierCount;
	Signature signature;
}CertificateOfMembership;

CertificateOfMembership * CertificateOfMembership_init(void);
bool CertificateOfMembership_sign(const Identity *with, CertificateOfMembership *com);
void CertificateOfMembership_serialize(Buffer *b, CertificateOfMembership *com);
unsigned int CertificateOfMembership_deserialize(Buffer *b, unsigned int startAt, CertificateOfMembership *com);
CertificateOfMembership *CertificateOfMembership_init2(uint64_t timestamp,uint64_t timestampMaxDelta,uint64_t nwid,const Address issuedTo);


#endif
