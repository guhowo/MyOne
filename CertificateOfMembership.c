#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "CertificateOfMembership.h"

CertificateOfMembership * CertificateOfMembership_init(void)
{
	CertificateOfMembership *p = NULL;

	p = malloc(sizeof(CertificateOfMembership));
	if(p){
		memset(p,0,sizeof(CertificateOfMembership));
	}

	return p;
}

bool CertificateOfMembership_sign(const Identity *with, CertificateOfMembership *com)
{
	uint64_t buf[ZT_NETWORK_COM_MAX_QUALIFIERS * 3];
	unsigned int ptr = 0;
	unsigned int i;
	
	for(i=0; i<com->_qualifierCount; ++i) {
		buf[ptr++] = Utils_hton_u64(com->_qualifiers[i].id);
		buf[ptr++] = Utils_hton_u64(com->_qualifiers[i].value);
		buf[ptr++] = Utils_hton_u64(com->_qualifiers[i].maxDelta);
	}

	if(!C25519_has_PrivateKey(with->_privateKey)){
		com->_signedBy = 0;
		return false;
	}
	C25519_sign4(com->_signature, with->_privateKey, with->_publicKey, buf, ptr * sizeof(uint64_t));
	com->_signedBy = with->_address;
	return true;
}

void CertificateOfMembership_serialize(Buffer *b, CertificateOfMembership *com)
{
	int i;
	append(b, (uint8_t)1);
	append_uint16(b, (uint16_t)com->_qualifierCount);
	for(i=0; i < com->_qualifierCount; ++i) {
		append_uint64(b, com->_qualifiers[i].id);
		append_uint64(b, com->_qualifiers[i].value);
		append_uint64(b, com->_qualifiers[i].maxDelta);
	}
	
	Address_AppendTo(b, com->_signedBy);
	if (com->_signedBy){
		append_databylen(b, com->_signature, ZT_C25519_SIGNATURE_LEN);
	}
	return;
}

unsigned int CertificateOfMembership_deserialize(Buffer *b, unsigned int startAt, CertificateOfMembership *com)
{
	unsigned int p = startAt;
	unsigned int numq;
	uint64_t lastId = 0;
	unsigned int i;
	
	com->_qualifierCount = 0;
	com->_signedBy = 0;

	if (b->b[p++] != 1){
		printf("invalid object.\n");
		return 0;
	}

	numq = at_u16(b, p);
	p += sizeof(uint16_t);
	
	for(i=0; i<numq; ++i) {
		const uint64_t qid = at_u64(b, p);
		if (qid < lastId){
			printf("qualifiers not sorted\n");
			return 0;
		}else{
			lastId = qid;
		}
		
		if (com->_qualifierCount < ZT_NETWORK_COM_MAX_QUALIFIERS) {
			com->_qualifiers[com->_qualifierCount].id = qid;
			com->_qualifiers[com->_qualifierCount].value = at_u64(b, p + 8);
			com->_qualifiers[com->_qualifierCount].maxDelta = at_u64(b, p + 16);
			p += 24;
			++(com->_qualifierCount);
		} else {
			printf("too many qualifiers\n");
			return 0;
		}
	}

	Address_SetTo(b->b + p, ZT_ADDRESS_LENGTH, &(com->_signedBy));
	p += ZT_ADDRESS_LENGTH;

	if (com->_signedBy) {
		memcpy(com->_signature, b->b + p, ZT_C25519_SIGNATURE_LEN);
		p += ZT_C25519_SIGNATURE_LEN;
	}

	return (p - startAt);
}

