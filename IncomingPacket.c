#include <stdio.h>
#include "IncomingPacket.h"
#include "Packet.h"
#include "Identity.h"
#include "Utils.h"
#include "C25519.h"
#include "RuntimeEnvironment.h"
#include "ZeroTierOne.h"
#include "Topology.h"
#include "Version.h"
#include "Path.h"


extern RuntimeEnvironment *RR;

bool expectingReplyTo(const uint64_t packetId)
{
/*
	const uint32_t pid2 = (uint32_t)(packetId >> 32);
	const unsigned long bucket = (unsigned long)(pid2 & ZT_EXPECTING_REPLIES_BUCKET_MASK1);
	for(unsigned long i=0;i<=ZT_EXPECTING_REPLIES_BUCKET_MASK2;++i) {
		if (_expectingRepliesTo[bucket][i] == pid2)
			return true;
	}
	return false;
*/
	return true;
	
}

bool _doHELLO(Path *path,Buffer *buf,const bool alreadyAuthenticated)
{
	unsigned char *data=buf->b;
	unsigned int len=buf->len;
	const uint64_t now = RR->now;
	const uint64_t pid = Utils_ntoh_u64(*(uint64_t *)&data[0]);
	Address fromAddress;
	memset(&fromAddress,0,sizeof(fromAddress));
	Address_SetTo(data+ZT_PACKET_IDX_SOURCE,ZT_ADDRESS_LENGTH,&fromAddress);
	const unsigned int protoVersion = data[ZT_PROTO_VERB_HELLO_IDX_PROTOCOL_VERSION];
	const unsigned int vMajor = data[ZT_PROTO_VERB_HELLO_IDX_MAJOR_VERSION];
	const unsigned int vMinor = data[ZT_PROTO_VERB_HELLO_IDX_MINOR_VERSION];
	const unsigned int vRevision = ntohs(*(uint16_t *)&data[ZT_PROTO_VERB_HELLO_IDX_REVISION]);
	const uint64_t timestamp = Utils_ntoh_u64(*(uint64_t *)&data[ZT_PROTO_VERB_HELLO_IDX_TIMESTAMP]);
	Identity id;
	unsigned int ptr = ZT_PROTO_VERB_HELLO_IDX_IDENTITY + Identity_Deserialize(&id,data,ZT_PROTO_VERB_HELLO_IDX_IDENTITY);

	printf("_doHELLO, HELLO from %s(%s)\n",Address_ToString(id._address),InetAddress_toString(&path->addr));
	if (protoVersion < ZT_PROTO_VERSION_MIN) {
		printf("dropped HELLO from %s: protocol version too old\n",Address_ToString(id._address));
		return true;
	}

	if (fromAddress != id._address) {
		printf("dropped HELLO from %s: identity does not match packet source address\n",Address_ToString(id._address));
		return true;
	}

	Peer *peer = Peer_GotByAddress(id._address);
	if (peer) {
		// We already have an identity with this address -- check for collisions
		if (!alreadyAuthenticated) {
			if (!Identity_IsEqual(&peer->id, &id)) {
				// Identity is different from the one we already have -- address collision	
				// need Check rate limits, to do list	
				uint8_t key[ZT_PEER_SECRET_KEY_LENGTH];
				if (Identity_Agree(&id,key,ZT_PEER_SECRET_KEY_LENGTH)) {
					if (Packet_Dearmor(buf, key)) { // ensure packet is authentic, otherwise drop
						printf("rejected HELLO from %s(%s): address already claimed\n",Address_ToString(id._address),InetAddress_toString(&path->addr));
						Buffer outp;
						Buffer_Init(&outp);
						Packet(&outp,id._address,RR->identity._address,VERB_ERROR);
						append(&outp, (unsigned char)VERB_HELLO);
						append_uint64(&outp,(uint64_t)pid);
						append(&outp,(uint8_t)ERROR_IDENTITY_COLLISION);
						Packet_Armor(&outp,key,true,nextOutgoingCounter(path));
						Path_Send(path,&outp,RR->now);
					} else {
						printf("rejected HELLO from %s: packet failed authentication\n",Address_ToString(id._address));
					}
				} else {
					printf("rejected HELLO from (%s): key agreement failed\n",Address_ToString(id._address));
				}
				return true;
			} else {
				// Identity is the same as the one we already have -- check packet integrity	
				if (!Packet_Dearmor(buf, peer->key)) {
					printf("rejected HELLO from %s: packet failed authentication\n",Address_ToString(id._address));
					return true;
				}
			}
		}
	}else {
		if (alreadyAuthenticated) {
			printf("dropped HELLO from %s: somehow already authenticated with unknown peer?\n",Address_ToString(id._address));
			return true;
		}

		// Check rate limits, need to do
		
		Peer newPeer;
		Peer_Init(&newPeer, &id);
		if (!Packet_Dearmor(buf,newPeer.key)) {
			printf("rejected HELLO from %s: packet failed authentication\n",Address_ToString(id._address));
			return true;
		}
		
		if (!Identity_LocallyValidate(&id)) {
			printf("dropped HELLO from %s: identity invalid\n",Address_ToString(id._address));
			return true;
		}

		peer = Topology_AddPeer(&newPeer);
	}

	// Get external surface address if present (was not in old versions)
	InetAddress externalSurfaceAddress;
	if (ptr < len) {
		ptr += InetAddress_Deserialize(&externalSurfaceAddress,data,ptr);
	}
	
	// Get primary planet world ID and world timestamp if present
	uint64_t planetWorldId = 0;
	uint64_t planetWorldTimestamp = 0;
	if ((ptr + 16) <= len) {
		planetWorldId = Utils_ntoh_u64(*(uint64_t *)&data[ptr]);
		ptr += 8;
		planetWorldTimestamp = Utils_ntoh_u64(*(uint64_t *)&data[ptr]);
		ptr += 8;
	}

	if (ptr < len) {
		// Remainder of packet, if present, is encrypted
		Packet_CryptField(peer->key,ptr,len - ptr);
	
		// Get moon IDs and timestamps if present
		if ((ptr + 2) <= len) {
			const unsigned int numMoons = Utils_ntoh_u64(*(uint16_t *)&data[ptr]);
			ptr += 2;
			unsigned int i;		
			for(i=0;i<numMoons;++i) {
				//need to do
				ptr += 16;
			}
		}
	
		// Handle COR if present (older versions don't send this)
		/* Segmentation fault
		if ((ptr + 2) <= len) {
			if ((*(uint16_t *)&data[ptr]) > 0) {
				CertificateOfRepresentation cor;
				ptr += 2;
				ptr += certificate_deserialize(&cor,data,len,ptr);
			} else ptr += 2;
		}
		*/
	}

	Buffer outp;
	Buffer_Init(&outp);
	Packet(&outp,id._address,RR->identity._address,VERB_OK);
	append(&outp,(unsigned char)VERB_HELLO);
	append_uint64(&outp,(uint64_t)pid);
	append_uint64(&outp,(uint64_t)timestamp);
	append(&outp,(unsigned char)ZT_PROTO_VERSION);
	append(&outp,(unsigned char)ZEROTIER_ONE_VERSION_MAJOR);
	append(&outp,(unsigned char)ZEROTIER_ONE_VERSION_MINOR);
	append_uint16(&outp,(uint16_t)ZEROTIER_ONE_VERSION_REVISION);

	if(protoVersion >= 5) {
		InetAddress_Serialize(&path->addr, &outp);
	} else {
		printf("protoVersion %d is invalid\n", protoVersion);
		return false;
	}

	const unsigned int worldUpdateSizeAt = outp.len;
	outp.len+=2; // make room for 16-bit size field
	if ((planetWorldId)&&(RR->pTopology->planet.ts > planetWorldTimestamp)&&(planetWorldId == RR->pTopology->planet.id)) {
		Topology_Serialize(&outp,false);
	}

	setAt(&outp, worldUpdateSizeAt, (uint16_t)(outp.len - (worldUpdateSizeAt + 2)));
	const unsigned int corSizeAt = outp.len;
	outp.len += 2;
	Topology_AppendCor(&outp);
	setAt(&outp,corSizeAt,(uint16_t)(outp.len - (corSizeAt + 2)));

	Packet_Armor(&outp,peer->key,true,nextOutgoingCounter(path));
	Path_Send(path,&outp,now);	
	setRemoteVersion(peer,protoVersion,vMajor,vMinor,vRevision);
	received(peer,path,hops(data),pid,VERB_HELLO,0,VERB_NOP,false);
	
	return true;

}


bool _doOK(Peer *peer,Path *path,Buffer *buf)
{
	unsigned char *data=buf->b;
	unsigned int len=buf->len;
	const enum Verb inReVerb = (enum Verb)data[ZT_PROTO_VERB_OK_IDX_IN_RE_VERB];
	const uint64_t inRePacketId = Utils_ntoh_u64(*(uint64_t *)&data[ZT_PROTO_VERB_OK_IDX_IN_RE_PACKET_ID]);

	if (!expectingReplyTo(inRePacketId)) {
		printf("%s(%s): OK(%s) DROPPED: not expecting reply to %.16llx \n",Address_ToString(peer->id._address),InetAddress_toString(&path->addr),verbString(inReVerb),inRePacketId);
		return true;
	}
		
	switch(inReVerb) {
		case VERB_HELLO: {
			const uint64_t latency = RR->now - Utils_ntoh_u64(*(uint64_t *)&data[ZT_PROTO_VERB_HELLO__OK__IDX_TIMESTAMP]);
			if (latency > ZT_HELLO_MAX_ALLOWABLE_LATENCY)
				return true;

			const unsigned int vProto = (unsigned int)data[ZT_PROTO_VERB_HELLO__OK__IDX_PROTOCOL_VERSION];
			const unsigned int vMajor = (unsigned int)data[ZT_PROTO_VERB_HELLO__OK__IDX_MAJOR_VERSION];
			const unsigned int vMinor = (unsigned int)data[ZT_PROTO_VERB_HELLO__OK__IDX_MINOR_VERSION];
			const unsigned int vRevision = (unsigned int)ntohs(*(uint16_t *)&data[ZT_PROTO_VERB_HELLO__OK__IDX_REVISION]);

			InetAddress externalSurfaceAddress;
			unsigned int ptr = ZT_PROTO_VERB_HELLO__OK__IDX_REVISION + 2;

			// Get reported external surface address if present
			if (ptr < len)
				ptr += InetAddress_Deserialize(&externalSurfaceAddress,data,ptr);

			// Handle planet or moon updates if present
			if ((ptr + 2) <= len) {
				const unsigned int worldsLen = (unsigned int)ntohs(*(uint16_t *)&data[ptr]);
				ptr += 2;
				if (Topology_IsInUpstreams(&peer->id._address)) {
					const unsigned int endOfWorlds = ptr + worldsLen;
					while (ptr < endOfWorlds) {
						World w;
						ptr += Topology_Deserialize(&w,&w.roots,data,ptr);
						Topology_AddWorld(&w,false);
					}
				} else {
					ptr += worldsLen;
				}
			}

			// Handle certificate of representation if present
			if ((ptr + 2) <= len) {
				ptr += 2;
				setRemoteVersion(peer,vProto,vMajor,vMinor,vRevision);
				//maybe need to do iam
			} break;
		}

		case VERB_WHOIS:
		case VERB_NETWORK_CONFIG_REQUEST:
		case VERB_MULTICAST_GATHER:
		case VERB_MULTICAST_FRAME: 
		default: 
			printf("Other types of Packet\n");
			break;
	}
	
	received(peer,path,hops(data),Utils_ntoh_u64(*(uint64_t *)&data[0]),VERB_OK,inRePacketId,inReVerb,false);
	
	return true;
}

bool tryDecode(Path *path,Buffer *buf)
{	
	unsigned char *data=buf->b;
	unsigned int len=buf->len;
	Address srcZta;
	memset(&srcZta,0,sizeof(srcZta));
	Address_SetTo(data+ZT_PACKET_IDX_SOURCE,ZT_ADDRESS_LENGTH,&srcZta);		//get 40bits source zt address
	const unsigned int c = Packet_Cipher(data);
	enum Verb v = (enum Verb)(data[ZT_PACKET_IDX_VERB] & 0x1f);
	if ((c == ZT_PROTO_CIPHER_SUITE__C25519_POLY1305_NONE)&&(v == VERB_HELLO)) {
		// Only HELLO is allowed in the clear, but will still have a MAC
		printf(">> HELLO from %s(%s)\n",Address_ToString(srcZta),InetAddress_toString(&path->addr));
		return _doHELLO(path,buf,false);
	}

	Peer *pPeer = Peer_GotByAddress(srcZta);
	if (pPeer) {
		printf(">> %s from %s(%s)\n",verbString(v),Address_ToString(srcZta),InetAddress_toString(&path->addr));
		switch(v) {
				case VERB_HELLO:                      return _doHELLO(path,buf,true);
				case VERB_OK:                         return _doOK(pPeer,path,buf);
				default:
					//peer->received(tPtr,_path,hops(),packetId(),v,0,Packet::VERB_NOP,false);
					printf("ignore unknown verbs\n");
					return true;
			}
	} else {
		//requestWhois(srcZta);
		return false;
	}
	
}

void onRemotePacket(Path *path,const InetAddress *localAddr,const InetAddress *fromAddr,Buffer *buf)
{
	unsigned char *data=buf->b;
	unsigned int len=buf->len;
	if(len == 13) {
		/* LEGACY: before VERB_PUSH_DIRECT_PATHS, peers used broadcast
		* announcements on the LAN to solve the 'same network problem.' We
		* no longer send these, but we'll listen for them for a while to
		* locate peers with versions <1.0.4. */		
	} else if(len > ZT_PROTO_MIN_FRAGMENT_LENGTH) {		//len>16
		if(((uint8_t *)data)[ZT_PACKET_FRAGMENT_IDX_FRAGMENT_INDICATOR] == ZT_PACKET_FRAGMENT_INDICATOR) {
			// Handle fragment ----------------------------------------------------
			if(!RR->pTopology->amRoot && !Path_TrustEstablished(path, RR->now)) {
				printf("handle fragment, not Root and nontrusted path\n");
				return;
			}
						
		} else if (len >= ZT_PROTO_MIN_PACKET_LENGTH) {
			Address destination;
			Address_SetTo(data+8,ZT_ADDRESS_LENGTH,&destination);
			Address source;
			Address_SetTo(data+13,ZT_ADDRESS_LENGTH,&source);
			if(source == RR->identity._address) {
				printf("Source %s is RR\n",Address_ToString(destination));
				return;
			}
			if(destination != RR->identity._address) {
				printf("destination %s is NOT RR\n",Address_ToString(destination));
				if(!RR->pTopology->amRoot && !Path_TrustEstablished(path, RR->now)) {
					printf("not amRoot && nontrusted Path\n");	
					return;
				}
				//need to do 
				return;
			} else if((((uint8_t *)data)[ZT_PACKET_IDX_FLAGS] & 0x40) != 0) {
				printf("destination %s is RR, try decode\n",Address_ToString(destination));
				const uint64_t packetId = (
					(((uint64_t)((const uint8_t *)data)[0]) << 56) |
					(((uint64_t)((const uint8_t *)data)[1]) << 48) |
					(((uint64_t)((const uint8_t *)data)[2]) << 40) |
					(((uint64_t)((const uint8_t *)data)[3]) << 32) |
					(((uint64_t)((const uint8_t *)data)[4]) << 24) |
					(((uint64_t)((const uint8_t *)data)[5]) << 16) |
					(((uint64_t)((const uint8_t *)data)[6]) << 8) |
					((uint64_t)((const uint8_t *)data)[7])
				);
			} else {
				printf("Packet is unfragmented, so just process it\n");
				if(!tryDecode(path,buf)) {
					//need to do
				}
				return;
			}
		}
	}
		
}


enum ZT_ResultCode processWirePacket(const InetAddress *localAddr,const InetAddress *fromAddr,Buffer *buf)
{
	Path *path = Topology_GetPath(localAddr, fromAddr);
	path->lastIn = RR->now;

	onRemotePacket(path,localAddr,fromAddr,buf);
	return ZT_RESULT_OK;
}

void phyOnDatagram(int socket,const struct sockaddr *localAddr,const struct sockaddr *from,Buffer *buf)
{
#if 0
	if ((len >= 16)&&(((const InetAddress *)(from))->scope() == IP_SCOPE_GLOBAL))
			_lastDirectReceiveFromGlobal = now();
#endif

	const enum ZT_ResultCode rc = processWirePacket((const InetAddress *)localAddr,(const InetAddress *)from,buf);
	if (ZT_ResultCode_isFatal(rc)) {
		printf("fatal error code from processWirePacket: %d\n",(int)rc);
	}	
}

