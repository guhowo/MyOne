#include "CertificateOfOwnership.h"

void CertificateOfOwnership_serialize(CertificateOfOwnership *coo, Buffer *buf,const bool forSign)
{
	unsigned int i,j;
	
	if (forSign){
		append_uint64(buf,(uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}
	
	append_uint64(buf, coo->_networkId);
	append_uint64(buf, coo->_ts);
	append_uint64(buf, coo->_flags);
	append_uint32(buf, coo->_id);
	append_uint16(buf, coo->_thingCount);

	for(i=0,j=coo->_thingCount;i<j;++i) {
		append(buf,(uint8_t)coo->_thingTypes[i]);
		append_databylen(buf, coo->_thingValues[i], ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE);
	}
	Address_AppendTo(buf, coo->_issuedTo);
	Address_AppendTo(buf, coo->_signedBy);

	if (!forSign) {
		append(buf, 1);
		append_uint16(buf, ZT_C25519_SIGNATURE_LEN);
		append_databylen(buf, coo->_signature, ZT_C25519_SIGNATURE_LEN);
	}

	append_uint16(buf, 0);// length of additional fields, currently 0

	if (forSign){
		append_uint64(buf,(uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}
	return;
}

unsigned int CertificateOfOwnership_deserialize(Buffer *buf, unsigned int startAt, CertificateOfOwnership *coo)
{
	unsigned int p = startAt;
	unsigned int i,j;

	memset(coo, 0, sizeof(CertificateOfOwnership));

	coo->_networkId = at_u64(buf, p);
	p += 8;
	coo->_ts = at_u64(buf, p);
	p += 8;
	coo->_flags = at_u64(buf, p);
	p += 8;
	coo->_id = at_u32(buf, p);
	p += 4;
	coo->_thingCount = at_u16(buf, p);
	p += 2;

	for(i=0,j=coo->_thingCount; i<j; ++i) {
		if (i < ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS) {
			coo->_thingTypes[i] = (uint8_t)buf->b[p++];
			memcpy(coo->_thingValues[i], buf->b + p, ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE);
			p += ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE;
		}
	}

	Address_SetTo(buf->b + p, ZT_ADDRESS_LENGTH, &(coo->_issuedTo));
	p += ZT_ADDRESS_LENGTH;
	Address_SetTo(buf->b + p, ZT_ADDRESS_LENGTH, &(coo->_signedBy));
	p += ZT_ADDRESS_LENGTH;

	if (buf->b[p++] == 1) {
		if (at_u16(buf, p) != ZT_C25519_SIGNATURE_LEN){
			printf("invalid signature length\n");
		}
		p += 2;
		memcpy(coo->_signature, buf->b + p, ZT_C25519_SIGNATURE_LEN);
		p += ZT_C25519_SIGNATURE_LEN;
	} else {
		p += 2 + at_u16(buf, p);		
	}

	p += 2 + at_u16(buf, p);
	
	return (p - startAt);
}

/**
 * @param signer Signing identity, must have private key
 * @return True if signature was successful
 */
bool CertificateOfOwnership_sign(const Identity *signer, CertificateOfOwnership *coo)
{
	Buffer tmp;
	
	if(C25519_has_PrivateKey(signer->_privateKey)){
		coo->_signedBy = signer->_address;
		CertificateOfOwnership_serialize(coo, &tmp, true);
		C25519_sign4(coo->_signature, signer->_privateKey, signer->_publicKey, tmp.b, tmp.len);
		return true;
	}
	return false;
}

