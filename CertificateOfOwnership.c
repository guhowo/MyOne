#include "CertificateOfOwnership.h"

void CertificateOfOwnership_serialize(CertificateOfOwnership *coo, Buffer *buf,const bool forSign)
{
    unsigned int i,j;
    
    if (forSign){
        append_uint64(buf,(uint64_t)0x7f7f7f7f7f7f7f7fULL);
    }
    
    append_uint64(buf, coo->networkId);
    append_uint64(buf, coo->ts);
    append_uint64(buf, coo->flags);
    append_uint32(buf, coo->id);
    append_uint16(buf, coo->thingCount);

    for(i=0,j=coo->thingCount;i<j;++i) {
        append(buf,(uint8_t)coo->thingTypes[i]);
        append_databylen(buf, coo->thingValues[i], ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE);
    }
    Address_AppendTo(buf, coo->issuedTo);
    Address_AppendTo(buf, coo->signedBy);

    if (!forSign) {
        append(buf, 1);
        append_uint16(buf, ZT_C25519_SIGNATURE_LEN);
        append_databylen(buf, coo->signature, ZT_C25519_SIGNATURE_LEN);
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

    coo->networkId = at_u64(buf, p);
    p += 8;
    coo->ts = at_u64(buf, p);
    p += 8;
    coo->flags = at_u64(buf, p);
    p += 8;
    coo->id = at_u32(buf, p);
    p += 4;
    coo->thingCount = at_u16(buf, p);
    p += 2;

    for(i=0,j=coo->thingCount; i<j; ++i) {
        if (i < ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS) {
            coo->thingTypes[i] = (uint8_t)buf->b[p++];
            memcpy(coo->thingValues[i], buf->b + p, ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE);
            p += ZT_CERTIFICATEOFOWNERSHIP_MAX_THING_VALUE_SIZE;
        }
    }

    Address_SetTo(buf->b + p, ZT_ADDRESS_LENGTH, &(coo->issuedTo));
    p += ZT_ADDRESS_LENGTH;
    Address_SetTo(buf->b + p, ZT_ADDRESS_LENGTH, &(coo->signedBy));
    p += ZT_ADDRESS_LENGTH;

    if (buf->b[p++] == 1) {
        if (at_u16(buf, p) != ZT_C25519_SIGNATURE_LEN){
            printf("invalid signature length\n");
        }
        p += 2;
        memcpy(coo->signature, buf->b + p, ZT_C25519_SIGNATURE_LEN);
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
    Buffer_Init(&tmp);
    
    if(C25519_has_PrivateKey(signer->_privateKey)){
        coo->signedBy = signer->_address;
        CertificateOfOwnership_serialize(coo, &tmp, true);
        C25519_sign4(coo->signature, signer->_privateKey, signer->_publicKey, tmp.b, tmp.len);
        return true;
    }
    return false;
}

void CertificateOfOwnership_init(CertificateOfOwnership *coo,const uint64_t nwid,const uint64_t ts,const Address issuedTo,const uint32_t id)
{
    coo->networkId = nwid;
    coo->ts = ts;
    coo->flags = 0;
    coo->id = id;
    coo->thingCount = 0;
    coo->issuedTo = issuedTo;
    memset(coo->thingTypes,0,sizeof(coo->thingTypes));
    memset(coo->thingValues,0,sizeof(coo->thingTypes));

    return;
}

void CertificateOfOwnership_addThingIp(CertificateOfOwnership *coo,const InetAddress *ip)
{
    if (coo->thingCount >= ZT_CERTIFICATEOFOWNERSHIP_MAX_THINGS)
        return;
    
    if (ip->address.ss_family == AF_INET) {
        coo->thingTypes[coo->thingCount] = THING_IPV4_ADDRESS;
        memcpy(coo->thingValues[coo->thingCount],&(((const struct sockaddr_in *)&ip)->sin_addr.s_addr),4);
        ++coo->thingCount;
    } else if (ip->address.ss_family == AF_INET6) {
        coo->thingTypes[coo->thingCount] = THING_IPV6_ADDRESS;
        memcpy(coo->thingValues[coo->thingCount],((const struct sockaddr_in6 *)&ip)->sin6_addr.s6_addr,16);
        ++coo->thingCount;
    }
}


