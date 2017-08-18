#include <memory.h>
#include "Packet.h"
#include "salsa20.h"
#include "Version.h"
#include "RuntimeEnvironment.h"
#include "Poly1305.h"
#include "Identity.h"
#include "Peer.h"

const unsigned char ZERO_KEY[32] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

extern RuntimeEnvironment *RR;		//one.c
extern 	int udp_sockd;

void Packet_SetAddress(Buffer *buf, const Address addr)
{
	unsigned char *b = (unsigned char *)buf->b + buf->len;
	*(b++) = (unsigned char)((addr >> 32) & 0xff);
	*(b++) = (unsigned char)((addr >> 24) & 0xff);
	*(b++) = (unsigned char)((addr >> 16) & 0xff);
	*(b++) = (unsigned char)((addr >> 8) & 0xff);
	*b = (unsigned char)(addr & 0xff);
}
		
void Packet(Buffer *buf, const Address dest, const Address source, const enum Verb v)
{
	getSecureRandom((void *)buf->b, 8);
	buf->len += 8;
	Packet_SetAddress(buf, dest);
	buf->len += ZT_ADDRESS_LENGTH;
	Packet_SetAddress(buf, source);
	buf->len += ZT_ADDRESS_LENGTH;
	buf->b[ZT_PACKET_IDX_FLAGS] = 0; // zero flags and hops
	buf->b[ZT_PACKET_IDX_VERB] = (char)v;		//setVerb()
	buf->len = ZT_PACKET_IDX_VERB + 1;
}


static void _salsa20MangleKey(Buffer *buf, const unsigned char *in,unsigned char *out)
{
	const unsigned char *d=buf->b;
	const unsigned int len=buf->len;
	// IV and source/destination addresses. Using the addresses divides the
	// key space into two halves-- A->B and B->A (since order will change).
	unsigned int i;
	for(i=0;i<18;++i) // 8 + (ZT_ADDRESS_LENGTH * 2) == 18
		out[i] = in[i] ^ d[i];

	// Flags, but with hop count masked off. Hop count is altered by forwarding
	// nodes. It's one of the only parts of a packet modifiable by people
	// without the key.
	out[18] = in[18] ^ (d[ZT_PACKET_IDX_FLAGS] & 0xf8);

	// Raw packet size in bytes -- thus each packet size defines a new
	// key space.
	out[19] = in[19] ^ (unsigned char)(len & 0xff);
	out[20] = in[20] ^ (unsigned char)((len >> 8) & 0xff); // little endian

	// Rest of raw key is used unchanged
	for(i=21;i<32;++i)
		out[i] = in[i];
}

void Packet_Armor(Buffer *buf, const void *key,bool encryptPayload,unsigned int counter)
{
	encryptPayload = false;
	uint8_t mangledKey[32];
	uint8_t *const data = (uint8_t *)(buf->b);

	// Mask least significant 3 bits of packet ID with counter to embed packet send counter for QoS use
	data[7] = (data[7] & 0xf8) | (uint8_t)(counter & 0x07);

	// Set flag now, since it affects key mangle function
	Packet_SetCipher(buf, encryptPayload ? ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_SALSA2012 : ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_NONE);
	_salsa20MangleKey(buf,(const unsigned char *)key,mangledKey);
	
	Salsa20 s20;
	Salsa20_init(&s20,mangledKey,data + ZT_PACKET_IDX_IV);
	uint64_t macKey[4];
	Salsa20_crypt12(&s20,(const void *)ZERO_KEY,(void *)macKey,sizeof(macKey));
	uint8_t *const payload = data + ZT_PACKET_IDX_VERB;
	const unsigned int payloadLen = buf->len - ZT_PACKET_IDX_VERB;
	if (encryptPayload) {
		Salsa20_crypt12(&s20,payload,payload,payloadLen);
	}
	uint64_t mac[2];
	Poly1305_compute(mac,payload,payloadLen,macKey);
	memcpy(data + ZT_PACKET_IDX_MAC,mac,8);

}

unsigned int Packet_Cipher(unsigned char *data)
{
	return (((unsigned int)data[ZT_PACKET_IDX_FLAGS] & 0x38) >> 3);
}

bool Packet_Dearmor(Buffer *buf, const void *key)
{
	unsigned char *data=buf->b;
	unsigned int dlen=buf->len;
	uint8_t mangledKey[32];
	const unsigned int payloadLen = dlen - ZT_PACKET_IDX_VERB;
	unsigned char *const payload = data + ZT_PACKET_IDX_VERB;
	const unsigned int cs = Packet_Cipher(data);
	Salsa20 s20;
	uint64_t macKey[4];
	uint64_t mac[2];
	
	if ((cs == ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_NONE)||(cs == ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_SALSA2012)) {
		_salsa20MangleKey(buf, (const unsigned char *)key,mangledKey);
		Salsa20_init(&s20,mangledKey,data + ZT_PACKET_IDX_IV);
		Salsa20_crypt12(&s20, ZERO_KEY,macKey,sizeof(macKey));
		Poly1305_compute(mac,payload,payloadLen,macKey);
#ifdef ZT_NO_TYPE_PUNNING
		if (!Utils_secureEq(mac,data + ZT_PACKET_IDX_MAC,8))
			return false;
#else
		if ((*(const uint64_t *)(data + ZT_PACKET_IDX_MAC)) != mac[0]) // also secure, constant time
			return false;
#endif
		if (cs == ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_SALSA2012)
			 Salsa20_crypt12(&s20, payload,payload,payloadLen);

		return true;
	} else {
		return false; // unrecognized cipher suite
	}
}


bool udpSend(const struct sockaddr *remoteAddress,const Buffer *buf)
{	
	fprintf(stderr, "<< %s is Sended to remoteAddress %s\n", verbString((enum Verb)(*(((unsigned char *)buf->b)+ZT_PACKET_IDX_VERB) & 0x1f)), inet_ntoa(((struct sockaddr_in *)remoteAddress)->sin_addr));
	return ((long)sendto(udp_sockd,(void *)buf->b,buf->len,0,remoteAddress,(remoteAddress->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))==(long)buf->len);
}


int nodeWirePacketSendFunction(const struct sockaddr_storage *localAddr,const struct sockaddr_storage *addr, const Buffer *buf)
{
	return udpSend((struct sockaddr *)addr,buf);
}


void sendHELLO(Peer *peer, const InetAddress *localAddr,const InetAddress *atAddress,uint64_t _now,unsigned int counter)
{	
	Buffer outp;	//packet buffer
	Buffer_Init(&outp);

	Packet(&outp, peer->id._address,RR->identity._address,VERB_HELLO);
	append(&outp, (unsigned char)ZT_PROTO_VERSION);
	append(&outp, (unsigned char)ZEROTIER_ONE_VERSION_MAJOR);
	append(&outp, (unsigned char)ZEROTIER_ONE_VERSION_MINOR);
	append_uint16(&outp, (uint16_t)ZEROTIER_ONE_VERSION_REVISION);
	append_uint64(&outp, _now);
	Identity_Serialize(&RR->identity, &outp,false);
	InetAddress_Serialize(atAddress, &outp);

	append_uint64(&outp, (uint64_t)RR->pTopology->planet.id);
	append_uint64(&outp, (uint64_t)RR->pTopology->planet.ts);

	const unsigned int startCryptedPortionAt = outp.len;
	append_uint16(&outp, (uint16_t)0);		//moons.size() + moonsWanted.size() == 0
	const unsigned int corSizeAt = outp.len;
	
	outp.len += 2;
	Topology_AppendCor(&outp);
	setAt(&outp, corSizeAt, (uint16_t)(outp.len - (corSizeAt + 2)));
	//RR->node->expectReplyTo(outp.packetId());
	if (atAddress) {
		Packet_Armor(&outp, peer->key,false,counter); // false == don't encrypt full payload, but add MAC
		nodeWirePacketSendFunction(&(localAddr->address), &(atAddress->address),&outp);
		const char *tmpAt = InetAddress_toString(atAddress);
		printf("send(HELLO) to destination: %s\n",tmpAt);
	} else {
		//RR->sw->send(tPtr,outp,false); // false == don't encrypt full payload, but add MAC
	}

	
}


const char *verbString(enum Verb v)
{
	switch(v) {
		case VERB_NOP: return "NOP";
		case VERB_HELLO: return "HELLO";
		case VERB_ERROR: return "ERROR";
		case VERB_OK: return "OK";
		case VERB_WHOIS: return "WHOIS";
		case VERB_RENDEZVOUS: return "RENDEZVOUS";
		case VERB_FRAME: return "FRAME";
		case VERB_EXT_FRAME: return "EXT_FRAME";
		case VERB_ECHO: return "ECHO";
		case VERB_MULTICAST_LIKE: return "MULTICAST_LIKE";
		case VERB_NETWORK_CREDENTIALS: return "NETWORK_CREDENTIALS";
		case VERB_NETWORK_CONFIG_REQUEST: return "NETWORK_CONFIG_REQUEST";
		case VERB_NETWORK_CONFIG: return "NETWORK_CONFIG";
		case VERB_MULTICAST_GATHER: return "MULTICAST_GATHER";
		case VERB_MULTICAST_FRAME: return "MULTICAST_FRAME";
		case VERB_PUSH_DIRECT_PATHS: return "PUSH_DIRECT_PATHS";
		case VERB_USER_MESSAGE: return "USER_MESSAGE";
	}
	return "(unknown)";
}


void Packet_CryptField(const void *key,unsigned int start,unsigned int len)
{
	return;
}






