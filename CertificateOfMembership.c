#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "CertificateOfMembership.h"
#include "Topology.h"
#include "Switch.h"
#include "Network.h"

CertificateOfMembership * CertificateOfMembership_init(void)
{
    CertificateOfMembership *p = NULL;

    p = (CertificateOfMembership *)malloc(sizeof(CertificateOfMembership));
    if(p){
        memset(p,0,sizeof(CertificateOfMembership));
    }

    return p;
}

CertificateOfMembership *CertificateOfMembership_init2(uint64_t timestamp,uint64_t timestampMaxDelta,uint64_t nwid,const Address issuedTo)
{
    CertificateOfMembership *p=CertificateOfMembership_init();
    p->qualifiers[0].id = COM_RESERVED_ID_TIMESTAMP;
    p->qualifiers[0].value = timestamp;
    p->qualifiers[0].maxDelta = timestampMaxDelta;
    p->qualifiers[1].id = COM_RESERVED_ID_NETWORK_ID;
    p->qualifiers[1].value = nwid;
    p->qualifiers[1].maxDelta = 0;
    p->qualifiers[2].id = COM_RESERVED_ID_ISSUED_TO;
    p->qualifiers[2].value = issuedTo;
    p->qualifiers[2].maxDelta = 0xffffffffffffffffULL;
    p->qualifierCount = 3;
}

bool CertificateOfMembership_sign(const Identity *with, CertificateOfMembership *com)
{
    uint64_t buf[ZT_NETWORK_COM_MAX_QUALIFIERS * 3];
    unsigned int ptr = 0;
    unsigned int i;
    
    for(i=0; i<com->qualifierCount; ++i) {
        buf[ptr++] = Utils_hton_u64(com->qualifiers[i].id);
        buf[ptr++] = Utils_hton_u64(com->qualifiers[i].value);
        buf[ptr++] = Utils_hton_u64(com->qualifiers[i].maxDelta);
    }

    if(!C25519_has_PrivateKey(with->_privateKey)){
        com->signedBy = 0;
        return false;
    }
    C25519_sign4(com->signature, with->_privateKey, with->_publicKey, buf, ptr * sizeof(uint64_t));
    com->signedBy = with->_address;
    return true;
}

void CertificateOfMembership_serialize(Buffer *b, CertificateOfMembership *com)
{
    int i;
    append(b, (uint8_t)1);
    append_uint16(b, (uint16_t)com->qualifierCount);
    for(i=0; i < com->qualifierCount; ++i) {
        append_uint64(b, com->qualifiers[i].id);
        append_uint64(b, com->qualifiers[i].value);
        append_uint64(b, com->qualifiers[i].maxDelta);
    }
    
    Address_AppendTo(b, com->signedBy);
    if (com->signedBy){
        append_databylen(b, com->signature, ZT_C25519_SIGNATURE_LEN);
    }
    return;
}

unsigned int CertificateOfMembership_deserialize(Buffer *b, unsigned int startAt, CertificateOfMembership *com)
{
    unsigned int p = startAt;
    unsigned int numq;
    uint64_t lastId = 0;
    unsigned int i;
    
    com->qualifierCount = 0;
    com->signedBy = 0;

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
        
        if (com->qualifierCount < ZT_NETWORK_COM_MAX_QUALIFIERS) {
            com->qualifiers[com->qualifierCount].id = qid;
            com->qualifiers[com->qualifierCount].value = at_u64(b, p + 8);
            com->qualifiers[com->qualifierCount].maxDelta = at_u64(b, p + 16);
            p += 24;
            ++(com->qualifierCount);
        } else {
            printf("too many qualifiers\n");
            return 0;
        }
    }

    Address_SetTo(b->b + p, ZT_ADDRESS_LENGTH, &(com->signedBy));
    p += ZT_ADDRESS_LENGTH;

    if (com->signedBy) {
        memcpy(com->signature, b->b + p, ZT_C25519_SIGNATURE_LEN);
        p += ZT_C25519_SIGNATURE_LEN;
    }

    return (p - startAt);
}

uint64_t COM_networkId(CertificateOfMembership *com)
{
    unsigned int i=0;
    for(i = 0;i<com->qualifierCount;++i) {
        if (com->qualifiers[i].id == COM_RESERVED_ID_NETWORK_ID)
            return com->qualifiers[i].value;
    }
    return 0ULL;
}


int CertificateOfMembership_verify(CertificateOfMembership *com)
{
    unsigned int i;
    if ((!com->signedBy)||(com->signedBy != (COM_networkId(com) >> 24) & 0xffffffffffULL)||(com->qualifierCount > ZT_NETWORK_COM_MAX_QUALIFIERS)){
        return -1;
    }

    
    Identity *id = Topology_getIdentity(com->signedBy);    

    if(!id){
        Switch_requestWhois(com->signedBy);
        return 1;
    }

    uint64_t buf[ZT_NETWORK_COM_MAX_QUALIFIERS * 3];
    unsigned int ptr = 0;
    for(i = 0;i < com->qualifierCount; ++i) {
        buf[ptr++] = Utils_hton_u64(com->qualifiers[i].id);
        buf[ptr++] = Utils_hton_u64(com->qualifiers[i].value);
        buf[ptr++] = Utils_hton_u64(com->qualifiers[i].maxDelta);
    }
    return (C25519_verify(id->_publicKey, buf, ptr * sizeof(uint64_t), com->signature) ? 0 : -1);
}

Address COM_issuedTo(CertificateOfMembership *com)
{
    unsigned int i = 0;
    for(i = 0;i < com->qualifierCount; ++i) {
        if (com->qualifiers[i].id == COM_RESERVED_ID_ISSUED_TO)
            return com->qualifiers[i].value;
    }
    return 0;
}


