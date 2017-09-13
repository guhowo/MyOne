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
#include "Dictionary.h"
#include "NetworkController.h"
#include "Switch.h"

extern RuntimeEnvironment *RR;
// For tracking packet IDs to filter out OK/ERROR replies to packets we did not send
uint8_t _expectingRepliesToBucketPtr[ZT_EXPECTING_REPLIES_BUCKET_MASK1 + 1];
uint32_t _expectingRepliesTo[ZT_EXPECTING_REPLIES_BUCKET_MASK1 + 1][ZT_EXPECTING_REPLIES_BUCKET_MASK2 + 1];

void expectReplyTo(const uint64_t packetId)
{
    const unsigned long pid2 = (unsigned long)(packetId >> 32);
    const unsigned long bucket = (unsigned long)(pid2 & ZT_EXPECTING_REPLIES_BUCKET_MASK1);
    _expectingRepliesTo[bucket][_expectingRepliesToBucketPtr[bucket]++ & ZT_EXPECTING_REPLIES_BUCKET_MASK2] = (uint32_t)pid2;
	return;
}

bool expectingReplyTo(const uint64_t packetId)
{
    const uint32_t pid2 = (uint32_t)(packetId >> 32);
    const unsigned long bucket = (unsigned long)(pid2 & ZT_EXPECTING_REPLIES_BUCKET_MASK1);
	unsigned long i;
    for(i=0;i<=ZT_EXPECTING_REPLIES_BUCKET_MASK2;++i) {
        if (_expectingRepliesTo[bucket][i] == pid2)
            return true;
    }
    return false;
}

void _sendErrorNeedCredentials(Path *path,Peer *peer,Buffer *buf,const uint64_t nwid)
{
	unsigned char *data=buf->b;
	uint64_t _now = RR->now;
	if (Peer_rateGateOutgoingComRequest(peer,_now)) {
		Buffer outp;
		Buffer_Init(&outp);
		Address source;
		memset(&source,0,sizeof(source));
		enum Verb v = (enum Verb)(data[ZT_PACKET_IDX_VERB] & 0x1f);		
		Address_SetTo(data+ZT_PACKET_IDX_SOURCE,ZT_ADDRESS_LENGTH,&source);
		const int PacketId = Utils_ntoh_u64(*(uint64_t *)&data[0]);
		
		Packet(&outp,source,RR->identity._address,VERB_ERROR);
		append(&outp,(uint8_t)v);
		append_uint64(&outp,PacketId);
		append(&outp,(uint8_t)ERROR_NEED_MEMBERSHIP_CERTIFICATE);
		append_uint64(&outp,nwid);
		unsigned int counter = nextOutgoingCounter(path);
		Packet_Armor(&outp,peer->key,true,counter);
		Path_Send(path,&outp,_now);	
	}
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


bool _doWHOIS(Peer *peer,Path *path,Buffer *buf)
{
	if((RR->pTopology->amRoot==false) && (!Peer_rateGateInboundWhoisRequest(peer, RR->now))) {
		return true;
	}

	unsigned char *data=buf->b;
	unsigned int length=buf->len;
	Buffer outp;
	Buffer_Init(&outp);
	uint64_t PacketId = Utils_ntoh_u64(*(uint64_t *)&data[0]);
	Packet(&outp,peer->id._address,RR->identity._address,VERB_OK);
	append(&outp,VERB_WHOIS);
	append_uint64(&outp,PacketId);

	unsigned int count = 0;
	unsigned int ptr = ZT_PACKET_IDX_PAYLOAD;
	while ((ptr + ZT_ADDRESS_LENGTH) <= length) {
		Address addr = 0;
		Address_SetTo(data+ptr,ZT_ADDRESS_LENGTH,&addr);
		ptr += ZT_ADDRESS_LENGTH;

		Identity *id=Topology_getIdentity(addr);
		if(id==NULL) {
			// Request unknown WHOIS from upstream from us (if we have one)
			//printf("_doWHOIS : whois address = %s\n",Address_ToString(addr));
			Switch_requestWhois(addr);
		} else {
			Identity_Serialize(id,&outp,false);
			++count;
		}
	}

	if (count > 0) {
		Packet_Armor(&outp,peer->key,true,nextOutgoingCounter(path));
		Path_Send(path,&outp,RR->now);
	}
	
	received(peer,path,hops(data),PacketId,VERB_WHOIS,0,VERB_NOP,false);
	return true;	
}

bool shouldUsePathForZeroTierTraffic(const Address ztaddr, const InetAddress *localAddress,const InetAddress *remoteAddress)
{
	if (!Path_isAddressValidForPath(remoteAddress)){
		return false;
    }

	if (Topology_isProhibitedEndpoint(ztaddr,remoteAddress)){
		return false;
    }
    
    //peer has config, controller and planet has no networkconfig
/*
	{
		Mutex::Lock _l(_networks_m);
		Hashtable< uint64_t,SharedPtr<Network> >::Iterator i(_networks);
		uint64_t *k = (uint64_t *)0;
		SharedPtr<Network> *v = (SharedPtr<Network> *)0;
		while (i.next(k,v)) {
			if ((*v)->hasConfig()) {
				for(unsigned int k=0;k<(*v)->config().staticIpCount;++k) {
					if ((*v)->config().staticIps[k].containsAddress(remoteAddress))
						return false;
				}
			}
		}
	}
*/    
    //pathCheckFunction no deal
	return true;
}


bool _doRENDEZVOUS(Peer *peer,Path *path,Buffer *buf)
{
    unsigned char *data = buf->b;
    int len = buf->len;
	const uint64_t requestPacketId = Utils_ntoh_u64(*(uint64_t *)&data[ZT_PACKET_IDX_IV]);

    if(!Topology_IsInUpstreams(&peer->id._address)){
        printf("RENDEZVOUS from %s ignored since source is not upstream\n", Address_ToString(peer->id._address));
    }else{
        char *peerid = Address_ToString(peer->id._address);
        char *pPath = InetAddress_toString(&path->addr);
        Address with;
        Address_SetTo(data + ZT_PROTO_VERB_RENDEZVOUS_IDX_ZTADDRESS, ZT_ADDRESS_LENGTH, &with);
        PeerNode *rendezvousWith = Topology_GetPeerNode(with);
        if(rendezvousWith){
            const unsigned int port = at_u16(buf, ZT_PROTO_VERB_RENDEZVOUS_IDX_PORT);
            const unsigned int addrlen = data[ZT_PROTO_VERB_RENDEZVOUS_IDX_ADDRLEN];
            if((port > 0)&&((addrlen == 4)||(addrlen == 16))){
                InetAddress atAddr;
                InetAddress_setFromBytes(&atAddr, data + ZT_PROTO_VERB_RENDEZVOUS_IDX_ADDRESS, addrlen, port);                    
                char *pwith = Address_ToString(with);
                char *patAddr = InetAddress_toString(&atAddr);
                if(shouldUsePathForZeroTierTraffic(with, &path->localAddress, &atAddr)){
                    Buffer tmpBuf;
                    Buffer_Init(&tmpBuf);
                    strcpy(tmpBuf.b, "ABRE");
                    tmpBuf.len = 4;
                    
                    nodeWirePacketSendFunction(&path->localAddress.address, &atAddr.address, &tmpBuf);
                    attemptToContactAt(&rendezvousWith->peer, &path->localAddress, &atAddr, RR->now, false, 0);

                    printf("RENDEZVOUS from %s says %s might be at %s, sent verification attempt\n", peerid, pwith, patAddr);
                }else{
                    printf("RENDEZVOUS from %s says %s might be at %s, ignoring since path is not suitable\n", peerid, pwith, patAddr);

                }
                free(pwith);
                free(patAddr);
            }else{
                printf("dropped corrupt RENDEZVOUS from %s(%s) (bad address or port)\n", peerid, pPath);

            }
        }else{
				printf("ignored RENDEZVOUS from %s(%s) to meet unknown peer %s\n", peerid, pPath);
		}
        free(peerid);
        free(pPath);
    }
	received(peer, path, hops(data),requestPacketId,VERB_RENDEZVOUS,0,VERB_NOP,false);
    return true;
}



bool _doMULTICAST_LIKE(Peer *peer,Path *path,Buffer *buf)
{
    return true;
}

bool _doNETWORK_CONFIG_REQUEST(Peer *peer,Path *path,Buffer *buf)
{
	unsigned char *data=buf->b;
	unsigned int len=buf->len;
	const uint64_t nwid = Utils_ntoh_u64(*(uint64_t *)&data[ZT_PROTO_VERB_NETWORK_CONFIG_REQUEST_IDX_NETWORK_ID]);
	const unsigned int hopCount = hops(data);
	const uint64_t requestPacketId = Utils_ntoh_u64(*(uint64_t *)&data[ZT_PACKET_IDX_IV]);

	if (RR->localNetworkController) {
		const unsigned int metaDataLength = (ZT_PROTO_VERB_NETWORK_CONFIG_REQUEST_IDX_DICT_LEN <= len) ? ntohs(*(uint16_t *)&data[ZT_PROTO_VERB_NETWORK_CONFIG_REQUEST_IDX_DICT_LEN]) : 0;
		const char *metaDataBytes = (metaDataLength != 0) ? (const char *)&data[ZT_PROTO_VERB_NETWORK_CONFIG_REQUEST_IDX_DICT] : (const char *)0;
		Dictionary metaData;
		metaData.len=metaDataLength;
		Dictionary_Init(&metaData,metaDataBytes);
		InetAddress zero;
		memset(&zero,0,sizeof(InetAddress));
		InetAddress fromAddress;
		memcpy(&fromAddress,(hopCount>0)?&zero:&path->addr,sizeof(InetAddress)); //Is that right?
		NetworkController_Request(nwid,&fromAddress,requestPacketId,&peer->id,&metaData);	
	} else {
			Buffer outp;
			Packet(&outp,peer->id._address,RR->identity._address,VERB_ERROR);
			append(&outp,(unsigned char)VERB_NETWORK_CONFIG_REQUEST);
			append_uint64(&outp,requestPacketId);
			append(&outp,(unsigned char)ERROR_UNSUPPORTED_OPERATION);
			append(&outp,nwid);
			Packet_Armor(&outp,peer->key,true,nextOutgoingCounter(path));
			Path_Send(path,&outp,RR->now);	
	} 
	received(peer,path,hops(data),requestPacketId,VERB_NETWORK_CONFIG_REQUEST,0,VERB_NOP,false);

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
		case VERB_NETWORK_CONFIG_REQUEST:
		case VERB_WHOIS:
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

	Peer *peer = Peer_GotByAddress(srcZta);
	printf(">> %s from %s(%s)\n",verbString(v),Address_ToString(srcZta),InetAddress_toString(&path->addr));
	if (peer) {
		switch(v) {
				case VERB_HELLO:                      return _doHELLO(path,buf,true);
				case VERB_OK:                         return _doOK(peer,path,buf);
				case VERB_NETWORK_CONFIG_REQUEST:	  return _doNETWORK_CONFIG_REQUEST(peer,path,buf);
				case VERB_MULTICAST_LIKE:			  return _doMULTICAST_LIKE(peer,path,buf);
				case VERB_WHOIS:					  return _doWHOIS(peer,path,buf);
                case VERB_RENDEZVOUS:                 return _doRENDEZVOUS(peer,path,buf);
				default:
					//peer->received(tPtr,_path,hops(),packetId(),v,0,Packet::VERB_NOP,false);
					printf("ignore unknown verbs\n");
					return true;
			}
	} else {
		Switch_requestWhois(srcZta);
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
	} else if(len > ZT_PROTO_MIN_FRAGMENT_LENGTH) {		// SECURITY: min length check is important since we do some C-style stuff below!
		if(((uint8_t *)data)[ZT_PACKET_FRAGMENT_IDX_FRAGMENT_INDICATOR] == ZT_PACKET_FRAGMENT_INDICATOR) { // Handle fragment
			if(!RR->pTopology->amRoot && !Path_TrustEstablished(path, RR->now)) { 
				printf("handle fragment, not Root and nontrusted path\n");
				return;
			}
						
		} else if (len >= ZT_PROTO_MIN_PACKET_LENGTH) { // min length check is important!
			Address destination,source;
			Address_SetTo(data+8,ZT_ADDRESS_LENGTH,&destination);
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

				Buffer outp;
				Buffer_Init(&outp);
				append_databylen(&outp,data,len);

				unsigned char hp=0;
				if(hops(data) < ZT_RELAY_MAX_HOPS) {
					hp=Packet_incrementHops(data);
					printf("hops=%d\n",(unsigned int)hp);
				
					Peer *relayTo = Peer_GotByAddress(destination);
					if((relayTo)&&Peer_sendDirect(relayTo,buf,RR->now,false)) {
						if((source!=RR->identity._address)&&(Switch_shouldUnite(RR->now,source,destination))) {// don't send RENDEZVOUS for cluster frontplane relays
							InetAddress *hintToSource = (InetAddress *)0;
							InetAddress *hintToDest = (InetAddress *)0;

							InetAddress destV4,destV6;
							InetAddress sourceV4,sourceV6;
							Peer_getRendezvousAddresses(relayTo,RR->now,&destV4,&destV6);

							Peer *sourcePeer=Peer_GotByAddress(source);
							if(sourcePeer) {
								Peer_getRendezvousAddresses(sourcePeer,RR->now,&sourceV4,&sourceV6);
								if (destV6.address.ss_family && (sourceV6.address.ss_family)) {
									hintToSource = &destV6;
									hintToDest = &sourceV6;
								} else if (destV4.address.ss_family && sourceV4.address.ss_family) {
									hintToSource = &destV4;
									hintToDest = &sourceV4;
								}

								if ((hintToSource)&&(hintToDest)) {
									unsigned int alt = (unsigned int)prng() & 1;
									const unsigned int completed = alt + 2;
									while (alt != completed) {
										Buffer outp;
										Buffer_Init(&outp);
										if ((alt & 1) == 0) {
											Packet(&outp,source,RR->identity._address,VERB_RENDEZVOUS);
											append(&outp,(uint8_t)0);
											Address_AppendTo(&outp,destination);
											append_uint16(&outp,(uint16_t)InetAddress_netmaskBits(hintToSource));
											if (hintToSource->address.ss_family == AF_INET6) {
												append(&outp,(uint8_t)16);
												append_databylen(&outp,InetAddress_rawIpData(hintToSource),16);
											} else {
												append(&outp,(uint8_t)4);
												append_databylen(&outp,InetAddress_rawIpData(hintToSource),4);
											}
											Switch_send(&outp,true);
										} else {
											Packet(&outp,destination,RR->identity._address,VERB_RENDEZVOUS);
											append(&outp,(uint8_t)0);
											Address_AppendTo(&outp,source);
											append_uint16(&outp,(uint16_t)InetAddress_netmaskBits(hintToDest));
											if (hintToDest->address.ss_family == AF_INET6) {
												append(&outp,(uint8_t)16);
												append_databylen(&outp,InetAddress_rawIpData(hintToDest),16);
											} else {
												append(&outp,(uint8_t)4);
												append_databylen(&outp,InetAddress_rawIpData(hintToDest),4);
											}
											Switch_send(&outp,true);
										}
										++alt;
									}
								}
							}
						}
					}else {
						relayTo = Topology_getUpstreamPeer(&source,1,true);
						if (relayTo)
							Peer_sendDirect(relayTo,buf,RR->now,true);
					}
				}
			} else if((((uint8_t *)data)[ZT_PACKET_IDX_FLAGS] & 0x40) != 0) {
				// Packet is the head of a fragmented packet series
				printf("destination %s is RR, Packet is fragmented\n",Address_ToString(destination));				
			} else {
				printf("Packet is unfragmented, so just process it\n");
				if(!tryDecode(path,buf)) {
					//need to do
					printf("try Decode failed!\n");
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

