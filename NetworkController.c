#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include"NetworkController.h"
#include"RuntimeEnvironment.h"
#include"Buffer.h"
#include"Packet.h"
#include"Identity.h"
#include"ZeroTierOne.h"
#include"json/json_object.h"
#include "CertificateOfMembership.h"

// Min duration between requests for an address/nwid combo to prevent floods
#define ZT_NETCONF_MIN_REQUEST_PERIOD 1000
#define MAX(a,b) (a)>(b)?(a):(b)
#define MIN(a,b) (a)<(b)?(a):(b)


extern NetworkController controller;
extern RuntimeEnvironment *RR;

bool findInetAddr(InetAddrList *head, InetAddress *addr)
{
	InetAddrList *tmp;
	list_for_each_entry(tmp, &head->list, list) {
        if(!memcmp(&tmp->InetAddr, addr, sizeof(struct sockaddr_storage))){
            return true;
        }
	}
	return false;
}

static bool _parseRule(json_object *r,ZT_VirtualNetworkRule *rule)
{
	if (json_object_get_type(r) != json_type_object)
		return false;

	const char *t=json_object_get_string(json_object_object_get(r,"type"));
	memset(rule,0,sizeof(ZT_VirtualNetworkRule));

	if (json_object_get_boolean(json_object_object_get(r,"not")))
		rule->t = 0x80;
	else rule->t = 0x00;
	if (json_object_get_boolean(json_object_object_get(r,"or")))
		rule->t |= 0x40;

	bool tag = false;
	if (strcmp(t, "ACTION_DROP")==0) {
		rule->t |= ZT_NETWORK_RULE_ACTION_DROP;
		return true;
	} else if (strcmp(t, "ACTION_ACCEPT")==0) {
		rule->t |= ZT_NETWORK_RULE_ACTION_ACCEPT;
		return true;
	} else if (strcmp(t, "ACTION_TEE")==0) {
		rule->t |= ZT_NETWORK_RULE_ACTION_TEE;
		rule->v.fwd.address = Utils_hexStrToU64(json_object_get_string(json_object_object_get(r,"address"))) & 0xffffffffffULL;
		rule->v.fwd.flags = (uint32_t)json_object_get_int64(json_object_object_get(r,"flags")) & 0xffffffffULL;
		rule->v.fwd.length = (uint16_t)json_object_get_int64(json_object_object_get(r,"length")) & 0xffffULL;
		return true;
	} else if (strcmp(t, "ACTION_WATCH")==0) {
		rule->t |= ZT_NETWORK_RULE_ACTION_WATCH;
		rule->v.fwd.address = Utils_hexStrToU64(json_object_get_string(json_object_object_get(r,"address"))) & 0xffffffffffULL;
		rule->v.fwd.flags = (uint32_t)json_object_get_int64(json_object_object_get(r,"flags")) & 0xffffffffULL;
		rule->v.fwd.length = (uint16_t)json_object_get_int64(json_object_object_get(r,"length")) & 0xffffULL;
		return true;
	} else if (strcmp(t, "ACTION_REDIRECT")==0) {
		rule->t |= ZT_NETWORK_RULE_ACTION_REDIRECT;
		rule->v.fwd.address = Utils_hexStrToU64(json_object_get_string(json_object_object_get(r,"address"))) & 0xffffffffffULL;
		rule->v.fwd.flags = (uint32_t)json_object_get_int64(json_object_object_get(r,"flags")) & 0xffffffffULL;
		return true;
	} else if (strcmp(t, "ACTION_BREAK")==0) {
		rule->t |= ZT_NETWORK_RULE_ACTION_BREAK;
		return true;
	} else if (strcmp(t, "MATCH_SOURCE_ZEROTIER_ADDRESS")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_SOURCE_ZEROTIER_ADDRESS;	
		rule->v.zt = Utils_hexStrToU64(json_object_get_string(json_object_object_get(r,"zt"))) & 0xffffffffffULL;
		return true;
	} else if (strcmp(t, "MATCH_DEST_ZEROTIER_ADDRESS")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_DEST_ZEROTIER_ADDRESS;
		rule->v.zt = Utils_hexStrToU64(json_object_get_string(json_object_object_get(r,"zt"))) & 0xffffffffffULL;
		return true;
	} else if (strcmp(t, "MATCH_VLAN_ID")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_VLAN_ID;
		rule->v.vlanId = (uint16_t)json_object_get_int64(json_object_object_get(r,"vlanId")) & 0xffffULL;
		return true;
	} else if (strcmp(t, "MATCH_VLAN_PCP")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_VLAN_PCP;
		rule->v.vlanId = (uint8_t)json_object_get_int64(json_object_object_get(r,"vlanPcp")) & 0xffULL;
		return true;
	} else if (strcmp(t, "MATCH_VLAN_DEI")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_VLAN_DEI;
		rule->v.vlanDei = (uint8_t)json_object_get_int64(json_object_object_get(r,"vlanDei")) & 0xffULL;
		return true;
	} else if (strcmp(t, "MATCH_MAC_SOURCE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_MAC_SOURCE;
		const char *mac = json_object_get_string(json_object_object_get(r,"mac"));
		Utils_unhex(mac,(unsigned int)strlen(mac),rule->v.mac,6);
		return true;
	} else if (strcmp(t, "MATCH_MAC_DEST")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_MAC_DEST;
		const char *mac = json_object_get_string(json_object_object_get(r,"mac"));
		Utils_unhex(mac,(unsigned int)strlen(mac),rule->v.mac,6);
		return true;
	} else if (strcmp(t, "MATCH_IPV4_SOURCE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IPV4_SOURCE;
		InetAddress ip;
		InetAddress_fromString(json_object_get_string(json_object_object_get(r,"ip")), &ip);
		rule->v.ipv4.ip = ((struct sockaddr_in *)&ip)->sin_addr.s_addr;
		rule->v.ipv4.mask = ((struct sockaddr_in *)&ip)->sin_port & 0xff;
		if (rule->v.ipv4.mask > 32) rule->v.ipv4.mask = 32;
		return true;
	} else if (strcmp(t, "MATCH_IPV4_DEST")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IPV4_DEST;
		InetAddress ip;
		InetAddress_fromString(json_object_get_string(json_object_object_get(r,"ip")), &ip);
		rule->v.ipv4.ip = ((struct sockaddr_in *)&ip)->sin_addr.s_addr;
		rule->v.ipv4.mask = ((struct sockaddr_in *)&ip)->sin_port & 0xff;
		if (rule->v.ipv4.mask > 32) rule->v.ipv4.mask = 32;
		return true;
	} else if (strcmp(t, "MATCH_IPV6_SOURCE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IPV6_SOURCE;
		InetAddress ip;
		InetAddress_fromString(json_object_get_string(json_object_object_get(r,"ip")), &ip);
		memcpy(rule->v.ipv6.ip,&(((struct sockaddr_in6 *)&ip)->sin6_addr.s6_addr),16);
		rule->v.ipv6.mask = ((struct sockaddr_in6 *)&ip)->sin6_port & 0xff;
		if (rule->v.ipv6.mask > 128) rule->v.ipv6.mask = 128;
		return true;
	} else if (strcmp(t, "MATCH_IPV6_DEST")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IPV6_DEST;
		InetAddress ip;
		InetAddress_fromString(json_object_get_string(json_object_object_get(r,"ip")), &ip);
		memcpy(rule->v.ipv6.ip,&(((struct sockaddr_in6 *)&ip)->sin6_addr.s6_addr),16);
		rule->v.ipv6.mask = ((struct sockaddr_in6 *)&ip)->sin6_port & 0xff;
		if (rule->v.ipv6.mask > 128) rule->v.ipv6.mask = 128;
		return true;
	} else if (strcmp(t, "MATCH_IP_TOS")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IP_TOS;
		rule->v.ipTos.mask = (uint8_t)(json_object_get_int64(json_object_object_get(r,"mask")) & 0xffULL);
		rule->v.ipTos.value[0] = (uint8_t)(json_object_get_int64(json_object_object_get(r,"start")) & 0xffULL);
		rule->v.ipTos.value[1] = (uint8_t)(json_object_get_int64(json_object_object_get(r,"end")) & 0xffULL);
		return true;
	} else if (strcmp(t, "MATCH_IP_PROTOCOL")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IP_PROTOCOL;
		rule->v.ipProtocol = (uint8_t)(json_object_get_int64(json_object_object_get(r,"ipProtocol")) & 0xffULL);
		return true;
	} else if (strcmp(t, "MATCH_ETHERTYPE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_ETHERTYPE;
		rule->v.etherType = (uint16_t)(json_object_get_int64(json_object_object_get(r,"etherType")) & 0xffffULL);
		return true;
	} else if (strcmp(t, "MATCH_ICMP")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_ICMP;
		rule->v.icmp.type = (uint8_t)(json_object_get_int64(json_object_object_get(r,"icmpType")) & 0xffULL);
		json_object *code = json_object_object_get(r,"icmpCode");
		if (json_object_get_type(code) == json_type_null) {
			rule->v.icmp.code = 0;
			rule->v.icmp.flags = 0x00;
		} else {
			rule->v.icmp.code = (uint8_t)(json_object_get_int64(code) & 0xffULL);
			rule->v.icmp.flags = 0x01;
		}
		return true;
	} else if (strcmp(t, "MATCH_IP_SOURCE_PORT_RANGE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IP_SOURCE_PORT_RANGE;
		rule->v.port[0] = (uint16_t)(json_object_get_int64(json_object_object_get(r,"start")) & 0xffffULL);
		rule->v.port[1] = (uint16_t)(json_object_get_int64(json_object_object_get(r,"end")) & 0xffffULL);
		return true;
	} else if (strcmp(t, "MATCH_IP_DEST_PORT_RANGE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_IP_DEST_PORT_RANGE;
		rule->v.port[0] = (uint16_t)(json_object_get_int64(json_object_object_get(r,"start")) & 0xffffULL);
		rule->v.port[1] = (uint16_t)(json_object_get_int64(json_object_object_get(r,"end")) & 0xffffULL);
		return true;
	} else if (strcmp(t, "MATCH_CHARACTERISTICS")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_CHARACTERISTICS;
		json_object *v = json_object_object_get(r, "mask");
		if (v!=NULL) {
			if (json_object_get_type(v) == json_type_double || json_object_get_type(v) == json_type_int) {
				rule->v.characteristics = json_object_get_int64(v);
			} else {
				const char *tmp = json_object_get_string(v);
				rule->v.characteristics = Utils_hexStrToU64(tmp);
			}
		}
		return true;
	} else if (strcmp(t, "MATCH_FRAME_SIZE_RANGE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_FRAME_SIZE_RANGE;
		rule->v.frameSize[0] = (uint16_t)(json_object_get_int64(json_object_object_get(r,"start")) & 0xffffULL);
		rule->v.frameSize[1] = (uint16_t)(json_object_get_int64(json_object_object_get(r,"end")) & 0xffffULL);
		return true;
	} else if (strcmp(t, "MATCH_RANDOM")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_RANDOM;
		rule->v.randomProbability = (uint32_t)(json_object_get_int64(json_object_object_get(r,"probability")) &  0xffffffffULL);
		return true;
	} else if (strcmp(t, "MATCH_TAGS_DIFFERENCE")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_TAGS_DIFFERENCE;
		tag = true;
	} else if (strcmp(t, "MATCH_TAGS_BITWISE_AND")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_AND;
		tag = true;
	} else if (strcmp(t, "MATCH_TAGS_BITWISE_OR")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_OR;
		tag = true;
	} else if (strcmp(t, "MATCH_TAGS_BITWISE_XOR")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_XOR;
		tag = true;
	} else if (strcmp(t, "MATCH_TAGS_EQUAL")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_TAGS_EQUAL;
		tag = true;
	} else if (strcmp(t, "MATCH_TAG_SENDER")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_TAG_SENDER;
		tag = true;
	} else if (strcmp(t, "MATCH_TAG_RECEIVER")==0) {
		rule->t |= ZT_NETWORK_RULE_MATCH_TAG_RECEIVER;
		tag = true;
	}
	if (tag) {
		rule->v.tag.id = (uint32_t)(json_object_get_int64(json_object_object_get(r,"id")) &  0xffffffffULL);
		rule->v.tag.value = (uint32_t)(json_object_get_int64(json_object_object_get(r,"value")) &  0xffffffffULL);
		return true;
	}

	return false;
}


Networks *findNetwork(uint64_t nwid)
{
	Networks *tmp;
	list_for_each_entry(tmp, &netWorks.list, list) {
		if(tmp->nwid == nwid)
			return tmp;
	}
	return NULL;

}

void ncSendError(uint64_t nwid,uint64_t requestPacketId,const Address destination,enum ncErrorCode errorCode)
{
	if (destination == RR->identity._address) {
		Networks *n=findNetwork(nwid);
		if (!n) return;
		switch(errorCode) {
			case NC_ERROR_OBJECT_NOT_FOUND:
			case NC_ERROR_INTERNAL_SERVER_ERROR:
				n->network.netconfFailure = NETCONF_FAILURE_NOT_FOUND;
				break;
			case NC_ERROR_ACCESS_DENIED:
				n->network.netconfFailure = NETCONF_FAILURE_ACCESS_DENIED;
				break;
			default: break;
		}
	} else if (requestPacketId) {
		Buffer outp;
		Packet(&outp,destination,RR->identity._address,VERB_ERROR);
		append(&outp,(unsigned char)VERB_NETWORK_CONFIG_REQUEST);
		append_uint64(&outp,requestPacketId);
		switch(errorCode) {
			case NC_ERROR_ACCESS_DENIED:
				append(&outp,(unsigned char)ERROR_NETWORK_ACCESS_DENIED_);
				break;			
			default:
				append(&outp,(unsigned char)ERROR_OBJ_NOT_FOUND);
				break;
		}
		append_uint64(&outp,nwid);
		Packet_trySend(&outp,true);
	}
}


void NetworkController_InitMember(json_object *member)
{
	return;
}

void getMemberStatus(MemberStatus *ms,const uint64_t nwid,const Identity *identity)
{
	return;
}


void _request(uint64_t nwid,const InetAddress *fromAddr,uint64_t requestPacketId,const Identity *identity,const Dictionary *metaData)
{
	char nwids[24];
	const uint64_t _now = now();
	json_object *network=NULL;
	json_object *member=NULL;
	bool origMember=true;
	NetworkSummaryInfo ns;

	if(requestPacketId) {
		MemberStatus ms;
		getMemberStatus(&ms,nwid,identity);
		
		if(_now - ms.lastRequestTime <= ZT_NETCONF_MIN_REQUEST_PERIOD)
			return;		
		ms.lastRequestTime = _now;
	}

	snprintf(nwids,sizeof(nwids),"%.16llx",nwid);
	if (!Jsondb_getNetworkAndMember(nwid,identity->_address,&network,&member,&ns)) {
		ncSendError(nwid,requestPacketId,identity->_address,NC_ERROR_OBJECT_NOT_FOUND);
		return;
	}
	
	if(!network||!member) {
		return;
	}

	const bool newMember = ((json_object_get_type(member)!=json_type_object)||(json_object_get_type(member)==json_type_null));
	NetworkController_InitMember(member);

	const char *haveIdstr=json_object_get_string(json_object_object_get(member,"identity"));
	if(haveIdstr && strlen(haveIdstr)>0) {
		Identity id;
		Identity_FromString(haveIdstr,&id);
		if(!Identity_IsEqual(&id,identity)) {
			ncSendError(nwid,requestPacketId,identity->_address,NC_ERROR_ACCESS_DENIED);
			return;
		}
	} else {
		// If we do not yet know this member's identity, learn it.
		char *IdentityStr=Identity_ToString(identity,false);
		json_object_set_string(json_object_object_get(member,"identity"),IdentityStr);
	}

	// These are always the same, but make sure they are set
	const char *addrs=Address_ToString(identity->_address);
	json_object *joId=json_object_object_get(member,"id");
	json_object_set_string(joId,addrs);
	json_object *joAddress=json_object_object_get(member,"address");
	json_object_set_string(joAddress,addrs);
	json_object *joNwid=json_object_object_get(member,"nwid");
	json_object_set_string(joNwid,nwids);
		
	// Determine whether and how member is authorized
	const char *authorizedBy = (const char *)0;
	bool autoAuthorized = false;
	json_bool autoAuthCredentialType,autoAuthCredential;	
	json_object *joAuthorized=json_object_object_get(member,"authorized");
	json_object *joPrivate=json_object_object_get(network,"private");
	if(json_object_get_boolean(joAuthorized)) {
		authorizedBy = "memberIsAuthorized";
	} else if(!json_object_get_boolean(joPrivate)) {
		authorizedBy = "networkIsPublic";		
		json_object *ahist=json_object_object_get(member,"authHistory");
		if ((json_object_get_type(ahist)!=json_type_array)||(json_object_get_type(member)==json_type_null))
			autoAuthorized = true;
	} else {
		//do nothing
	}

	// If we auto-authorized, update member record
	if ((autoAuthorized)&&(authorizedBy)) {
		json_object *joAuthorized=json_object_object_get(member,"authorized");
		json_object_set_boolean(joAuthorized,true);
		json_object *joNow=json_object_object_get(member,"lastAuthorizedTime");
		json_object_set_double(joAuthorized,_now);
		
		json_object *ah=json_object_new_object();		
		json_object_object_add(ah, "a", json_object_new_boolean(true));
		json_object_object_add(ah, "by", json_object_new_string(authorizedBy));
		json_object_object_add(ah, "ts", json_object_new_double((double)_now));
		json_object_object_add(ah, "ct", json_object_new_boolean(autoAuthCredentialType));		
		json_object_object_add(ah, "c", json_object_new_boolean(autoAuthCredential));
		json_object_object_add(member, "authHistory", ah);		
		
		json_object *revj = json_object_object_get(member,"revision");
		double reValue=(json_object_get_type(revj)==json_type_double)||(json_object_get_type(revj)==json_type_int) ? ((uint64_t)revj + 1ULL) : 1ULL;
		json_object_set_double(revj,reValue);	//set double or int?

	}

	if (authorizedBy) {
		if (requestPacketId) {
			const uint64_t vMajor = Dictionary_GetUI(metaData,ZT_NETWORKCONFIG_REQUEST_METADATA_KEY_NODE_MAJOR_VERSION,0);
			const uint64_t vMinor = Dictionary_GetUI(metaData,ZT_NETWORKCONFIG_REQUEST_METADATA_KEY_NODE_MINOR_VERSION,0);
			const uint64_t vRev = Dictionary_GetUI(metaData,ZT_NETWORKCONFIG_REQUEST_METADATA_KEY_NODE_REVISION,0);
			const uint64_t vProto = Dictionary_GetUI(metaData,ZT_NETWORKCONFIG_REQUEST_METADATA_KEY_PROTOCOL_VERSION,0);			
			json_object *jovMajor=json_object_object_get(member,"vMajor");
			json_object_set_int(jovMajor,vMajor);
			json_object *jovMinor=json_object_object_get(member,"vMinor");
			json_object_set_int(jovMinor,vMinor);
			json_object *jovRev=json_object_object_get(member,"vRev");
			json_object_set_int(jovRev,vRev);
			json_object *jovProto=json_object_object_get(member,"vProto");
			json_object_set_int(jovProto,vProto);

			MemberStatus ms;
			getMemberStatus(&ms,nwid,identity);
			ms.vMajor = (int)vMajor;
			ms.vMinor = (int)vMinor;
			ms.vRev = (int)vRev;
			ms.vProto = (int)vProto;
			memcpy(&ms.lastRequestMetaData,metaData,sizeof(Dictionary));
			memcpy(&ms.identity,identity,sizeof(Identity));
			
			if (fromAddr)
				memcpy(&ms.physicalAddr,fromAddr,sizeof(InetAddress));
			InetAddress tmpInetAddr;
			memset(&tmpInetAddr,0,sizeof(InetAddress));
			if (memcmp(&ms.physicalAddr,&tmpInetAddr,sizeof(tmpInetAddr))!=0) {
				json_object *jovphysicalAddr=json_object_object_get(member,"physicalAddr");
				json_object_set_string(jovphysicalAddr,InetAddress_toString(&ms.physicalAddr));
			}
		}

	} else {
		//removeMember
		return;
	}

	uint64_t credentialtmd = ZT_NETWORKCONFIG_DEFAULT_CREDENTIAL_TIME_MAX_MAX_DELTA;
	if (_now > ns.mostRecentDeauthTime) {
		// If we recently de-authorized a member, shrink credential TTL/max delta to
		// be below the threshold required to exclude it. Cap this to a min/max to
		// prevent jitter or absurdly large values.
		const uint64_t deauthWindow = _now - ns.mostRecentDeauthTime;
		if (deauthWindow < ZT_NETWORKCONFIG_DEFAULT_CREDENTIAL_TIME_MIN_MAX_DELTA) {
			credentialtmd = ZT_NETWORKCONFIG_DEFAULT_CREDENTIAL_TIME_MIN_MAX_DELTA;
		} else if (deauthWindow < (ZT_NETWORKCONFIG_DEFAULT_CREDENTIAL_TIME_MAX_MAX_DELTA + 5000ULL)) {
			credentialtmd = deauthWindow - 5000ULL;
		}
	}

	NetworkConfig nc;
	memset(&nc, 0, sizeof(NetworkConfig));
	nc.networkId = nwid;
	nc.type = json_object_get_boolean(json_object_object_get(network,"private")) ? ZT_NETWORK_TYPE_PRIVATE : ZT_NETWORK_TYPE_PUBLIC;
	nc.timestamp = _now;
	nc.credentialTimeMaxDelta = credentialtmd;
	nc.revision = json_object_get_int64(json_object_object_get(network,"revision"));
	nc.issuedTo = identity->_address;
	if (json_object_get_boolean(json_object_object_get(network,"enableBroadcast"))) nc.flags |= ZT_NETWORKCONFIG_FLAG_ENABLE_BROADCAST;
	if (json_object_get_boolean(json_object_object_get(network,"allowPassiveBridging"))) nc.flags |= ZT_NETWORKCONFIG_FLAG_ALLOW_PASSIVE_BRIDGING;
	strncpy(nc.name,json_object_get_string(json_object_object_get(network,"name")),sizeof(nc.name));
	nc.mtu = MAX(MIN((unsigned int)json_object_get_int64(json_object_object_get(network,"mtu")),(unsigned int)ZT_MAX_MTU),(unsigned int)ZT_MIN_MTU);
	nc.multicastLimit = (unsigned int)json_object_get_int64(json_object_object_get(network,"multicastLimit"));	
	
	//ns.activeBridges
	//json_object_put
	
	json_object *v4AssignMode = json_object_object_get(network,"v4AssignMode");
	json_object *v6AssignMode = json_object_object_get(network,"v6AssignMode");
	json_object *ipAssignmentPools = json_object_object_get(network,"ipAssignmentPools");
	json_object *routes = json_object_object_get(network,"routes");
	json_object *rules = json_object_object_get(network,"rules");
	json_object *capabilities = json_object_object_get(network,"capabilities");
	json_object *tags = json_object_object_get(network,"tags");	
	json_object *memberCapabilities = json_object_object_get(network,"capabilities");	
	json_object *memberTags = json_object_object_get(network,"tags");

	if (Dictionary_GetUI(metaData,ZT_NETWORKCONFIG_REQUEST_METADATA_KEY_RULES_ENGINE_REV,0) <= 0) {
		nc.ruleCount = 1;
		nc.rules[0].t = ZT_NETWORK_RULE_ACTION_ACCEPT;
	} else {
		if(json_object_get_type(rules)==json_type_array) {
			unsigned long i;
			for(i=0;i<json_object_array_length(rules);++i) {
				if (nc.ruleCount >= ZT_MAX_NETWORK_RULES)
					break;
				if (_parseRule(json_object_array_get_idx(rules,i),&nc.rules[nc.ruleCount]))	//operator overload
					++nc.ruleCount;
			}
		}

		//EmbededNetworkController.cpp 1340-1387 unfinished
	}
	
	if (json_object_get_type(routes)==json_type_array) {
		unsigned long i;
		for(i=0;i<json_object_array_length(rules);++i) {
			if (nc.routeCount >= ZT_MAX_NETWORK_ROUTES)
				break;
			json_object *route = json_object_array_get_idx(routes,i);
			json_object *target = json_object_object_get(route,"target");
			json_object *via = json_object_object_get(route,"via");
			if (json_object_get_type(routes)==json_type_string) {
				InetAddress t,v;
				InetAddress_fromString(json_object_get_string(target), &t);
				if (json_object_get_type(via)==json_type_string) 
					InetAddress_fromString(json_object_get_string(via), &v);
				if ((t.address.ss_family == AF_INET)||(t.address.ss_family == AF_INET6)) {
					ZT_VirtualNetworkRoute *r = &(nc.routes[nc.routeCount]);
					memcpy((InetAddress *)(&(r->target)), &t, sizeof(InetAddress));
					if (v.address.ss_family == t.address.ss_family)						
						memcpy((InetAddress *)(&(r->via)), &v, sizeof(InetAddress));
					++nc.routeCount;
				}
			}
		}
	}

	const bool noAutoAssignIps = json_object_get_boolean(json_object_object_get(member,"noAutoAssignIps"));

	if ((json_object_get_type(v6AssignMode)==json_type_object)&&(!noAutoAssignIps)) {
		if (json_object_get_boolean(json_object_object_get(v6AssignMode,"rfc4193"))&&(nc.staticIpCount < ZT_MAX_ZT_ASSIGNED_ADDRESSES)) {
			InetAddress_makeIpv6rfc4193(nwid,identity->_address,&(nc.staticIps[nc.staticIpCount++]));
			nc.flags |= ZT_NETWORKCONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION;
		}
		if (json_object_get_boolean(json_object_object_get(v6AssignMode,"6plane"))&&(nc.staticIpCount < ZT_MAX_ZT_ASSIGNED_ADDRESSES)) {
			InetAddress_makeIpv66plane(nwid,identity->_address,&(nc.staticIps[nc.staticIpCount++]));
			nc.flags |= ZT_NETWORKCONFIG_FLAG_ENABLE_IPV6_NDP_EMULATION;
		}
	}

	bool haveManagedIpv4AutoAssignment = false;
	bool haveManagedIpv6AutoAssignment = false;
	json_object *ipAssignments = json_object_object_get(member,"ipAssignments");
	if (json_object_get_type(ipAssignments) == json_type_array) {
		unsigned long i;
		for(i=0;i<json_object_object_length(ipAssignments);++i) {
			if (json_object_get_type(json_object_array_get_idx(ipAssignments,i))!=json_type_string)
				continue;
			const char *ips = json_object_get_string(json_object_array_get_idx(ipAssignments,i));
			InetAddress ip;
			InetAddress_fromString(ips,&ip);
	
			// IP assignments are only pushed if there is a corresponding local route. We also now get the netmask bits from
			// this route, ignoring the netmask bits field of the assigned IP itself. Using that was worthless and a source
			// of user error / poor UX.
			int routedNetmaskBits = 0;
			unsigned int rk;
			for(rk=0;rk<nc.routeCount;++rk) {
				if ( (!nc.routes[rk].via.ss_family) && InetAddress_containsAddress((const InetAddress *)&(nc.routes[rk].target),&ip))
					routedNetmaskBits = InetAddress_netmaskBits((const InetAddress *)(&(nc.routes[rk].target)));
				}
	
			if (routedNetmaskBits > 0) {
				if (nc.staticIpCount < ZT_MAX_ZT_ASSIGNED_ADDRESSES) {
					InetAddress_setPort(routedNetmaskBits, &ip);
					memcpy(&(nc.staticIps[nc.staticIpCount++]),&ip,sizeof(InetAddress));
				}
				if (ip.address.ss_family == AF_INET)
					haveManagedIpv4AutoAssignment = true;
				else if (ip.address.ss_family == AF_INET6)
					haveManagedIpv6AutoAssignment = true;
			}
		}
	} else {
			//need to do 	
		//ipAssignments = json::array();
	}

	if ( JSON_IS_ARRAY(ipAssignmentPools) && JSON_IS_OBJECT(v6AssignMode) && json_object_get_boolean(json_object_object_get(v6AssignMode,"zt")) && (!haveManagedIpv6AutoAssignment) && (!noAutoAssignIps) ) {
		unsigned long p;
		for(p=0;((p<json_object_array_length(ipAssignmentPools))&&(!haveManagedIpv6AutoAssignment));++p) {
			json_object *pool = json_object_array_get_idx(ipAssignmentPools, p);
			if (JSON_IS_OBJECT(pool)) {
				InetAddress ipRangeStart,ipRangeEnd;
				InetAddress_fromString(json_object_get_string(json_object_object_get(pool,"ipRangeStart")), &ipRangeStart);			
				InetAddress_fromString(json_object_get_string(json_object_object_get(pool,"ipRangeEnd")), &ipRangeEnd);
				if ( (ipRangeStart.address.ss_family == AF_INET6) && (ipRangeEnd.address.ss_family == AF_INET6) ) {
					uint64_t s[2],e[2],x[2],xx[2];
					memcpy(s,InetAddress_rawIpData(&ipRangeStart),16);
					memcpy(e,InetAddress_rawIpData(&ipRangeEnd),16);
					s[0] = Utils_ntoh_u64(s[0]);
					s[1] = Utils_ntoh_u64(s[1]);
					e[0] = Utils_ntoh_u64(e[0]);
					e[1] = Utils_ntoh_u64(e[1]);
					x[0] = s[0];
					x[1] = s[1];

					unsigned int trialCount;
					for(trialCount=0;trialCount<1000;++trialCount) {
						if ((trialCount == 0)&&(e[1] > s[1])&&((e[1] - s[1]) >= 0xffffffffffULL)) {
							// First see if we can just cram a ZeroTier ID into the higher 64 bits. If so do that.
							xx[0] = Utils_hton_u64(x[0]);
							xx[1] = Utils_hton_u64(x[1] + identity->_address);
						} else {
							getSecureRandom((void *)xx,16);
							if ((e[0] > s[0]))
								xx[0] %= (e[0] - s[0]);
							else xx[0] = 0;
							if ((e[1] > s[1]))
								xx[1] %= (e[1] - s[1]);
							else xx[1] = 0;
							xx[0] = Utils_hton_u64(x[0] + xx[0]);
							xx[1] = Utils_hton_u64(x[1] + xx[1]);
						}

						InetAddress ip6;		//need to do	

						// Check if this IP is within a local-to-Ethernet routed network
						int routedNetmaskBits = 0;
						unsigned int rk;
						for(rk=0;rk<nc.routeCount;++rk) {
							if ( (!nc.routes[rk].via.ss_family) && (nc.routes[rk].target.ss_family == AF_INET6) && 	InetAddress_containsAddress((const InetAddress *)&(nc.routes[rk].target),&ip6) )
								routedNetmaskBits = InetAddress_netmaskBits((const InetAddress *)&(nc.routes[rk].target));
						}

						// If it's routed, then try to claim and assign it and if successful end loop
						if ( (routedNetmaskBits > 0) && (!findInetAddr(&ns.allocatedIps,&ip6))) {
							json_object_array_add(ipAssignments,json_object_new_string(InetAddress_toString(&ip6)));
							json_object *tmpipAssignments=json_object_object_get(member,"ipAssignments");
							json_object_set_string(tmpipAssignments,json_object_get_string(ipAssignments));
							InetAddress_setPort((unsigned int)routedNetmaskBits, &ip6);
							if (nc.staticIpCount < ZT_MAX_ZT_ASSIGNED_ADDRESSES)
								nc.staticIps[nc.staticIpCount++] = ip6;
							haveManagedIpv6AutoAssignment = true;
							break;
						}
					}
				}
			}
		}
	}	

	

	
}


void NetworkController_Request(uint64_t nwid,const InetAddress *fromAddr,uint64_t requestPacketId,const Identity *identity,const Dictionary *metaData)
{
	unsigned char tmpZero[64] = {0};
	Identity tmpId;
	memset(&tmpId, 0, sizeof(Identity));
	bool hasSigningId = memcmp(&controller.signingId,&tmpId,sizeof(Identity))==0 ? true : false;
	bool hasPrivate = memcmp(controller.signingId._privateKey,tmpZero,64)==0 ? true : false; 
	if((!hasSigningId||!hasPrivate) ||(controller.signingId._address != (nwid >> 24)))		//sender?
		return;
	_request(nwid,fromAddr,requestPacketId,identity,metaData);
	return;
}

void NetworkController_Init()
{
	controller.startTime = now();
	memcpy(&controller.signingId,&RR->identity,sizeof(Identity));
	
	RR->localNetworkController=&controller;
}


