#ifndef _ZT_PACKET_H
#define _ZT_PACKET_H

#include <stdint.h>
#include <arpa/inet.h>

#include "Address.h"
#include "InetAddress.h"
#include "Constants.h"
#include "Buffer.h"
#include "Peer.h"

#define ZT_PROTO_VERSION 9
#define ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_NONE 0
#define ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_SALSA2012 1
#define ZT_PROTO_FLAG_ENCRYPTED 0x80
#define ZT_PROTO_MAX_PACKET_LENGTH (ZT_MAX_PACKET_FRAGMENTS * ZT_UDP_DEFAULT_PAYLOAD_MTU)
#define ZT_PACKET_IDX_IV 0
#define ZT_PACKET_IDX_DEST 8
#define ZT_PACKET_IDX_SOURCE 13
#define ZT_PACKET_IDX_FLAGS 18
#define ZT_PACKET_IDX_MAC 19
#define ZT_PACKET_IDX_VERB 27
#define ZT_PACKET_IDX_PAYLOAD 28

#define ZT_PROTO_VERSION_MIN 4
#define ZT_PROTO_MAX_HOPS 7

// Indexes of fields in fragment header
#define ZT_PACKET_FRAGMENT_IDX_PACKET_ID 0
#define ZT_PACKET_FRAGMENT_IDX_DEST 8
#define ZT_PACKET_FRAGMENT_IDX_FRAGMENT_INDICATOR 13
#define ZT_PACKET_FRAGMENT_IDX_FRAGMENT_NO 14
#define ZT_PACKET_FRAGMENT_IDX_HOPS 15
#define ZT_PACKET_FRAGMENT_IDX_PAYLOAD 16

#define ZT_PROTO_VERB_OK_IDX_IN_RE_VERB (ZT_PACKET_IDX_PAYLOAD)
#define ZT_PROTO_VERB_OK_IDX_IN_RE_PACKET_ID (ZT_PROTO_VERB_OK_IDX_IN_RE_VERB + 1)
#define ZT_PROTO_VERB_OK_IDX_PAYLOAD (ZT_PROTO_VERB_OK_IDX_IN_RE_PACKET_ID + 8)


#define ZT_PROTO_VERB_HELLO__OK__IDX_TIMESTAMP (ZT_PROTO_VERB_OK_IDX_PAYLOAD)
#define ZT_PROTO_VERB_HELLO__OK__IDX_PROTOCOL_VERSION (ZT_PROTO_VERB_HELLO__OK__IDX_TIMESTAMP + 8)
#define ZT_PROTO_VERB_HELLO__OK__IDX_MAJOR_VERSION (ZT_PROTO_VERB_HELLO__OK__IDX_PROTOCOL_VERSION + 1)
#define ZT_PROTO_VERB_HELLO__OK__IDX_MINOR_VERSION (ZT_PROTO_VERB_HELLO__OK__IDX_MAJOR_VERSION + 1)
#define ZT_PROTO_VERB_HELLO__OK__IDX_REVISION (ZT_PROTO_VERB_HELLO__OK__IDX_MINOR_VERSION + 1)



#define ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION (ZT_PACKET_IDX_PAYLOAD)
#define ZT_PROTO_VERB_HELLO_IDX_MAJOR_VERSION (ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION + 1)
#define ZT_PROTO_VERB_HELLO_IDX_MINOR_VERSION (ZT_PROTO_VERB_HELLO_IDX_MAJOR_VERSION + 1)
#define ZT_PROTO_VERB_HELLO_IDX_REVISION (ZT_PROTO_VERB_HELLO_IDX_MINOR_VERSION + 1)
#define ZT_PROTO_VERB_HELLO_IDX_TIMESTAMP (ZT_PROTO_VERB_HELLO_IDX_REVISION + 2)
#define ZT_PROTO_VERB_HELLO_IDX_IDENTITY (ZT_PROTO_VERB_HELLO_IDX_TIMESTAMP + 8)

/**
 * Magic number found at ZT_PACKET_FRAGMENT_IDX_FRAGMENT_INDICATOR
 */
#define ZT_PACKET_FRAGMENT_INDICATOR ZT_ADDRESS_RESERVED_PREFIX

#define ZT_PROTO_MIN_FRAGMENT_LENGTH ZT_PACKET_FRAGMENT_IDX_PAYLOAD
/**
 * Minimum viable packet length (a.k.a. header length)
 */
#define ZT_PROTO_MIN_PACKET_LENGTH ZT_PACKET_IDX_PAYLOAD

enum ErrorCode
{
	ERROR_NONE = 0x00,
	ERROR_INVALID_REQUEST = 0x01,
	ERROR_BAD_PROTOCOL_VERSION = 0x02,
	ERROR_OBJ_NOT_FOUND = 0x03,
	ERROR_IDENTITY_COLLISION = 0x04,
	ERROR_UNSUPPORTED_OPERATION = 0x05,
	ERROR_NEED_MEMBERSHIP_CERTIFICATE = 0x06,
	ERROR_NETWORK_ACCESS_DENIED_ = 0x07,
	ERROR_UNWANTED_MULTICAST = 0x08
};


const char *verbString(enum Verb v);
void Packet(Buffer *buf, const Address dest, const Address source, const enum Verb v);
void Packet_SetAddress(Buffer *buf, const Address addr);
void sendHELLO(Peer *peer,const InetAddress *localAddr,const InetAddress *atAddress,uint64_t _now,unsigned int counter);
bool udpSend(const struct sockaddr *remoteAddress,const Buffer *buf);
void Packet_Armor(Buffer *buf, const void *key,bool encryptPayload,unsigned int counter);
bool Packet_Dearmor(Buffer *buf, const void *key);
void Packet_CryptField(const void *key,unsigned int start,unsigned int len);
unsigned int Packet_Cipher(unsigned char *data);

static inline unsigned int hops(unsigned char *data)
{
	return ((unsigned int)data[ZT_PACKET_IDX_FLAGS] & 0x07);
}

static inline void Packet_SetCipher(Buffer *buf, unsigned int c)
{
	unsigned char b = buf->b[ZT_PACKET_IDX_FLAGS];
	b = (b & 0xc7) | (unsigned char)((c << 3) & 0x38); // bits: FFCCCHHH
	// Set DEPRECATED "encrypted" flag -- used by pre-1.0.3 peers
	if (c == ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_SALSA2012)
		b |= ZT_PROTO_FLAG_ENCRYPTED;
	else b &= (~ZT_PROTO_FLAG_ENCRYPTED);
	buf->b[ZT_PACKET_IDX_FLAGS] = b;
}


#endif
