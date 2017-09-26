#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "Revocation.h"

void Revocation_serialize(Buffer *buf,const bool forSign, Revocation *rev)
{
    if (forSign){
        append_uint64(buf, 0x7f7f7f7f7f7f7f7fULL);
    }
    append_uint32(buf, 0);
    append_uint32(buf, rev->_id);
    append_uint64(buf, rev->_networkId);
    append_uint32(buf, 0);
    append_uint32(buf, rev->_credentialId);
    append_uint64(buf, rev->_threshold);
    append_uint64(buf, rev->_flags);

    Address_AppendTo(buf, rev->_target);
    Address_AppendTo(buf, rev->_signedBy);
    append(buf, rev->_type);
    
    if (!forSign) {
        append(buf, 1);
        append_uint32(buf, ZT_C25519_SIGNATURE_LEN);
        append_databylen(buf, rev->_signature, ZT_C25519_SIGNATURE_LEN);
    }

    // This is the size of any additional fields, currently 0.
    append_uint16(buf, 0);

    if (forSign){
        append_uint64(buf, 0x7f7f7f7f7f7f7f7fULL);
    }
}

unsigned int Revocation_deserialize(Buffer *buf,unsigned int startAt, Revocation *rev)
{
    unsigned char *b = buf->b;
    memset(rev,0,sizeof(Revocation));

    unsigned int p = startAt;

    p += 4; // 4 bytes, currently unused

    rev->_id = at_u32(buf, p);
    p += 4;
    rev->_networkId = at_u64(buf, p);
    p += 8;    
    p += 4; // 4 bytes, currently unused
    rev->_credentialId = at_u32(buf, p);
    p += 4;
    rev->_threshold = at_u64(buf, p);
    p += 8;
    rev->_flags = at_u64(buf, p);
    p += 8;

    Address_SetTo(b + p, ZT_ADDRESS_LENGTH, &rev->_target);
    p += ZT_ADDRESS_LENGTH;

    Address_SetTo(b + p, ZT_ADDRESS_LENGTH, &rev->_signedBy);
    p += ZT_ADDRESS_LENGTH;
    rev->_type = b[p++];

    if (b[p++] == 1) {
        if (at_u16(buf, p) == ZT_C25519_SIGNATURE_LEN) {
            p += 2;
            memcpy(rev->_signature, b+p,ZT_C25519_SIGNATURE_LEN);
            p += ZT_C25519_SIGNATURE_LEN;
        } else{
            printf("invalid signature\n");
            return 0;
        } 
    } else {
        p += 2 + at_u16(buf, p);
    }

    p += 2 + at_u16(buf, p);

    return (p - startAt);
}


