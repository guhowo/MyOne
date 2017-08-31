#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Capability.h"

void Capability_serializeRules(Buffer *buf,const ZT_VirtualNetworkRule *rules, unsigned int ruleCount)
{
	unsigned char *b = buf->b;
	unsigned int i;
	
	for(i=0;i<ruleCount;++i) {
		// Each rule consists of its 8-bit type followed by the size of that type's
		// field followed by field data. The inclusion of the size will allow non-supported
		// rules to be ignored but still parsed.

		append(buf, rules[i].t);
		switch((enum ZT_VirtualNetworkRuleType)(rules[i].t & 0x3f)) {
			default:
				append(buf, 0);
				break;
			case ZT_NETWORK_RULE_ACTION_TEE:
			case ZT_NETWORK_RULE_ACTION_WATCH:
			case ZT_NETWORK_RULE_ACTION_REDIRECT:
				append(buf, 14);
				append_uint64(buf, rules[i].v.fwd.address);
				append_uint32(buf, rules[i].v.fwd.flags);
				append_uint16(buf, rules[i].v.fwd.length);
				break;
			case ZT_NETWORK_RULE_MATCH_SOURCE_ZEROTIER_ADDRESS:
			case ZT_NETWORK_RULE_MATCH_DEST_ZEROTIER_ADDRESS:
				append(buf, 5);
				Address_AppendTo(buf, rules[i].v.zt);
				break;
			case ZT_NETWORK_RULE_MATCH_VLAN_ID:
				append(buf, 2);
				append_uint16(buf, rules[i].v.vlanId);
				break;
			case ZT_NETWORK_RULE_MATCH_VLAN_PCP:
				append(buf, 1);
				append(buf, rules[i].v.vlanPcp);
				break;
			case ZT_NETWORK_RULE_MATCH_VLAN_DEI:
				append(buf, 1);
				append(buf, rules[i].v.vlanDei);
				break;
			case ZT_NETWORK_RULE_MATCH_MAC_SOURCE:
			case ZT_NETWORK_RULE_MATCH_MAC_DEST:
				append(buf, 6);
				append_databylen(buf, rules[i].v.mac, 6);
				break;
			case ZT_NETWORK_RULE_MATCH_IPV4_SOURCE:
			case ZT_NETWORK_RULE_MATCH_IPV4_DEST:
				append(buf, 5);
				append_databylen(buf, &(rules[i].v.ipv4.ip), 4);
				append(buf, rules[i].v.ipv4.mask);
				break;
			case ZT_NETWORK_RULE_MATCH_IPV6_SOURCE:
			case ZT_NETWORK_RULE_MATCH_IPV6_DEST:
				append(buf, 17);
				append_databylen(buf, rules[i].v.ipv6.ip, 16);
				append(buf, rules[i].v.ipv6.mask);
				break;
			case ZT_NETWORK_RULE_MATCH_IP_TOS:
				append(buf, 3);
				append(buf, rules[i].v.ipTos.mask);
				append(buf, rules[i].v.ipTos.value[0]);
				append(buf, rules[i].v.ipTos.value[1]);
				break;
			case ZT_NETWORK_RULE_MATCH_IP_PROTOCOL:
				append(buf, 1);
				append(buf, rules[i].v.ipProtocol);
				break;
			case ZT_NETWORK_RULE_MATCH_ETHERTYPE:
				append(buf, 2);
				append_uint16(buf, rules[i].v.etherType);
				break;
			case ZT_NETWORK_RULE_MATCH_ICMP:
				append(buf, 3);
				append(buf, rules[i].v.icmp.type);
				append(buf, rules[i].v.icmp.code);
				append(buf, rules[i].v.icmp.flags);
				break;
			case ZT_NETWORK_RULE_MATCH_IP_SOURCE_PORT_RANGE:
			case ZT_NETWORK_RULE_MATCH_IP_DEST_PORT_RANGE:
				append(buf, 4);
				append_uint16(buf, rules[i].v.port[0]);
				append_uint16(buf, rules[i].v.port[1]);
				break;
			case ZT_NETWORK_RULE_MATCH_CHARACTERISTICS:
				append(buf, 8);
				append_uint64(buf, rules[i].v.characteristics);
				break;
			case ZT_NETWORK_RULE_MATCH_FRAME_SIZE_RANGE:
				append(buf, 4);
				append_uint16(buf, rules[i].v.frameSize[0]);
				append_uint16(buf, rules[i].v.frameSize[1]);
				break;
			case ZT_NETWORK_RULE_MATCH_RANDOM:
				append(buf, 4);
				append_uint32(buf, rules[i].v.randomProbability);
				break;
			case ZT_NETWORK_RULE_MATCH_TAGS_DIFFERENCE:
			case ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_AND:
			case ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_OR:
			case ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_XOR:
			case ZT_NETWORK_RULE_MATCH_TAGS_EQUAL:
			case ZT_NETWORK_RULE_MATCH_TAG_SENDER:
			case ZT_NETWORK_RULE_MATCH_TAG_RECEIVER:
				append(buf, 8);
				append_uint32(buf, rules[i].v.tag.id);
				append_uint32(buf, rules[i].v.tag.value);
				break;
		}
	}
}

void Capability_deserializeRules(Buffer *buf, unsigned int *k, ZT_VirtualNetworkRule *rules, unsigned int *rc,const unsigned int maxRuleCount)
{
	unsigned char *b = buf->b;
	unsigned int p = *k;
	unsigned int ruleCount = *rc;
	
	while ((ruleCount < maxRuleCount)&&(p < 1024*50)) {
		rules[ruleCount].t = (uint8_t)b[p++];
		const unsigned int fieldLen = (unsigned int)b[p++];
		switch((enum ZT_VirtualNetworkRuleType)(rules[ruleCount].t & 0x3f)) {
			default:
				break;
			case ZT_NETWORK_RULE_ACTION_TEE:
			case ZT_NETWORK_RULE_ACTION_WATCH:
			case ZT_NETWORK_RULE_ACTION_REDIRECT:
				rules[ruleCount].v.fwd.address = at_u64(buf, p);
				rules[ruleCount].v.fwd.flags = at_u32(buf, p + 8);
				rules[ruleCount].v.fwd.length = at_u16(buf, p + 12);
				break;
			case ZT_NETWORK_RULE_MATCH_SOURCE_ZEROTIER_ADDRESS:
			case ZT_NETWORK_RULE_MATCH_DEST_ZEROTIER_ADDRESS:
				Address_SetTo(b + p, ZT_ADDRESS_LENGTH, &(rules[ruleCount].v.zt));
				break;
			case ZT_NETWORK_RULE_MATCH_VLAN_ID:
				rules[ruleCount].v.vlanId = at_u16(buf, p);
				break;
			case ZT_NETWORK_RULE_MATCH_VLAN_PCP:
				rules[ruleCount].v.vlanPcp = (uint8_t)b[p];
				break;
			case ZT_NETWORK_RULE_MATCH_VLAN_DEI:
				rules[ruleCount].v.vlanDei = (uint8_t)b[p];
				break;
			case ZT_NETWORK_RULE_MATCH_MAC_SOURCE:
			case ZT_NETWORK_RULE_MATCH_MAC_DEST:
				memcpy(rules[ruleCount].v.mac,b+p,6);
				break;
			case ZT_NETWORK_RULE_MATCH_IPV4_SOURCE:
			case ZT_NETWORK_RULE_MATCH_IPV4_DEST:
				memcpy(&(rules[ruleCount].v.ipv4.ip),b+p,4);
				rules[ruleCount].v.ipv4.mask = (uint8_t)b[p + 4];
				break;
			case ZT_NETWORK_RULE_MATCH_IPV6_SOURCE:
			case ZT_NETWORK_RULE_MATCH_IPV6_DEST:
				memcpy(rules[ruleCount].v.ipv6.ip,b+p,16);
				rules[ruleCount].v.ipv6.mask = (uint8_t)b[p + 16];
				break;
			case ZT_NETWORK_RULE_MATCH_IP_TOS:
				rules[ruleCount].v.ipTos.mask = (uint8_t)b[p];
				rules[ruleCount].v.ipTos.value[0] = (uint8_t)b[p+1];
				rules[ruleCount].v.ipTos.value[1] = (uint8_t)b[p+2];
				break;
			case ZT_NETWORK_RULE_MATCH_IP_PROTOCOL:
				rules[ruleCount].v.ipProtocol = (uint8_t)b[p];
				break;
			case ZT_NETWORK_RULE_MATCH_ETHERTYPE:
				rules[ruleCount].v.etherType = at_u16(buf, p);
				break;
			case ZT_NETWORK_RULE_MATCH_ICMP:
				rules[ruleCount].v.icmp.type = (uint8_t)b[p];
				rules[ruleCount].v.icmp.code = (uint8_t)b[p+1];
				rules[ruleCount].v.icmp.flags = (uint8_t)b[p+2];
				break;
			case ZT_NETWORK_RULE_MATCH_IP_SOURCE_PORT_RANGE:
			case ZT_NETWORK_RULE_MATCH_IP_DEST_PORT_RANGE:
				rules[ruleCount].v.port[0] = at_u16(buf, p);
				rules[ruleCount].v.port[1] = at_u16(buf, p + 2);
				break;
			case ZT_NETWORK_RULE_MATCH_CHARACTERISTICS:
				rules[ruleCount].v.characteristics = at_u64(buf, p);
				break;
			case ZT_NETWORK_RULE_MATCH_FRAME_SIZE_RANGE:
				rules[ruleCount].v.frameSize[0] = at_u16(buf, p);
				rules[ruleCount].v.frameSize[1] = at_u16(buf, p + 2);
				break;
			case ZT_NETWORK_RULE_MATCH_RANDOM:
				rules[ruleCount].v.randomProbability = at_u32(buf, p);
				break;
			case ZT_NETWORK_RULE_MATCH_TAGS_DIFFERENCE:
			case ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_AND:
			case ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_OR:
			case ZT_NETWORK_RULE_MATCH_TAGS_BITWISE_XOR:
			case ZT_NETWORK_RULE_MATCH_TAGS_EQUAL:
			case ZT_NETWORK_RULE_MATCH_TAG_SENDER:
			case ZT_NETWORK_RULE_MATCH_TAG_RECEIVER:
				rules[ruleCount].v.tag.id = at_u32(buf, p);
				rules[ruleCount].v.tag.value = at_u32(buf, p + 4);
				break;
		}
		p += fieldLen;
		++ruleCount;
	}
	*k = p;
	*rc = ruleCount;
	return;
}

void Capability_serialize(Buffer *buf,const bool forSign, Capability *cb)
{
	unsigned char *b = buf->b;
	unsigned int i;
	
	if (forSign){
		append_uint64(buf,(uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}

	// These are the same between Tag and Capability
	append_uint64(buf, cb->nwid);
	append_uint64(buf, cb->ts);
	append_uint32(buf, cb->id);
	append_uint16(buf, cb->ruleCount);
	
	Capability_serializeRules(buf, cb->rules, cb->ruleCount);
	
	append(buf, cb->maxCustodyChainLength);

	if (!forSign) {
		for(i=0;;++i) {
			if ((i < cb->maxCustodyChainLength)&&(i < ZT_MAX_CAPABILITY_CUSTODY_CHAIN_LENGTH)&&(cb->custody[i].to)) {
				Address_AppendTo(buf, cb->custody[i].to);
				Address_AppendTo(buf, cb->custody[i].from);
				
				append(buf, 1);
				append_uint16(buf, ZT_C25519_SIGNATURE_LEN);
				append_databylen(buf, cb->custody[i].signature, ZT_C25519_SIGNATURE_LEN);
			} else {
				Address_AppendTo(buf, 0);// zero 'to' terminates chain
				break;
			}
		}
	}

	// This is the size of any additional fields, currently 0.
	append_uint16(buf, 0);

	if (forSign){
		append_uint64(buf,(uint64_t)0x7f7f7f7f7f7f7f7fULL);
	}
}

unsigned int Capability_deserialize(Buffer *buf,unsigned int startAt, Capability *cb)
{
	unsigned char * b = buf->b;
	unsigned int i;
	Address to;
	
	memset(cb,0,sizeof(Capability));

	unsigned int p = startAt;

	cb->nwid = at_u64(buf, p); p += 8;
	cb->ts = at_u64(buf, p); p += 8;
	cb->id = at_u32(buf, p); p += 4;

	const unsigned int rc = at_u16(buf, p); p += 2;
	if (rc > ZT_MAX_CAPABILITY_RULES){
		printf("rule overflow\n");
		return 0;
	}
	Capability_deserializeRules(buf, &p, cb->rules, &(cb->ruleCount), rc);

	cb->maxCustodyChainLength = (unsigned int)b[p++];
	if ((cb->maxCustodyChainLength < 1)||(cb->maxCustodyChainLength > ZT_MAX_CAPABILITY_CUSTODY_CHAIN_LENGTH)){
		printf("invalid max custody chain length\n");
		return 0;
	}

	for(i=0;;++i) {
		Address_SetTo(b+p, ZT_ADDRESS_LENGTH, &to);
		p += ZT_ADDRESS_LENGTH;
		if (!to)
			break;
		if ((i >= cb->maxCustodyChainLength)||(i >= ZT_MAX_CAPABILITY_CUSTODY_CHAIN_LENGTH)){
			printf("unterminated custody chain\n");
			return 0;
		}
		cb->custody[i].to = to;
		Address_SetTo(b+p, ZT_ADDRESS_LENGTH,&(cb->custody[i].from));
		p += ZT_ADDRESS_LENGTH;
		
		if (b[p++] == 1) {
			if (at_u16(buf, p) != ZT_C25519_SIGNATURE_LEN){
				printf("invalid signature\n");
				return 0;
			}
			p += 2;
			memcpy(cb->custody[i].signature, b + p, ZT_C25519_SIGNATURE_LEN); p += ZT_C25519_SIGNATURE_LEN;
		} else {
			p += 2 + at_u16(buf, p);
		}
	}

	p += 2 + at_u16(buf, p);
	
	return (p - startAt);
}


