#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Tag.h"

void Tag_serialize(Buffer *buf,const bool forSign, Tag *tag)
{
	if (forSign){
		append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}

	append_uint64(buf, tag->networkId);
	append_uint64(buf, tag->ts);
	append_uint32(buf, tag->id);
	append_uint32(buf, tag->value);

	Address_AppendTo(buf, tag->issuedTo);
	Address_AppendTo(buf, tag->signedBy);

	if (!forSign) {
		append(buf, 1);
		append_uint16(buf, ZT_C25519_SIGNATURE_LEN);
		append_databylen(buf, tag->signature, ZT_C25519_SIGNATURE_LEN);
	}

	append_uint16(buf, 0); // length of additional fields, currently 0

	if (forSign){
		append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}
}

unsigned int Tag_deserialize(Buffer *buf,unsigned int startAt, Tag *tag)
{
	unsigned int p = startAt;
	unsigned char *b = buf->b;

	memset(tag,0,sizeof(Tag));

	tag->networkId = at_u64(buf, p); p += 8;
	tag->ts = at_u64(buf, p); p += 8;
	tag->id = at_u32(buf, p); p += 4;

	tag->value = at_u32(buf, p); p += 4;

	Address_SetTo(b + p, ZT_ADDRESS_LENGTH, &(tag->issuedTo)); p += ZT_ADDRESS_LENGTH;
	Address_SetTo(b + p, ZT_ADDRESS_LENGTH, &(tag->signedBy)); p += ZT_ADDRESS_LENGTH;

	if (b[p++] == 1) {
		if (at_u16(buf, p) != ZT_C25519_SIGNATURE_LEN){
			printf("invalid signature length\n");
			return 0;
		}
		p += 2;
		memcpy(tag->signature, b + p, ZT_C25519_SIGNATURE_LEN); p += ZT_C25519_SIGNATURE_LEN;
	} else {
		p += 2 + at_u16(buf, p);
	}

	p += 2 + at_u16(buf, p);
	
	return (p - startAt);
}


