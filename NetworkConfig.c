#include "NetworkConfig.h"
#include "Buffer.h"
#include "InetAddress.h"

#include <malloc.h>
#include <stdlib.h>


bool toDictionary(Dictionary *d, NetworkConfig *nc)
{
	Buffer tmp;
	memset(d,0,sizeof(Dictionary));

	// Try to put the more human-readable fields first

	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_VERSION,(uint64_t)ZT_NETWORKCONFIG_VERSION)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_NETWORK_ID,nc->networkId)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_TIMESTAMP,nc->timestamp)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_CREDENTIAL_TIME_MAX_DELTA,nc->credentialTimeMaxDelta)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_REVISION,nc->revision)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_ISSUED_TO,(uint64_t)nc->issuedTo)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_FLAGS,nc->flags)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_MULTICAST_LIMIT,(uint64_t)nc->multicastLimit)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_TYPE,(uint64_t)nc->type)) return false;
	if (!Dictionary_add(d,ZT_NETWORKCONFIG_DICT_KEY_NAME,nc->name,-1)) return false;
	if (!Dictionary_addUint64(d,ZT_NETWORKCONFIG_DICT_KEY_MTU,(uint64_t)nc->mtu)) return false;
		// Then add binary blobs

	if (nc->com.qualifierCount) {
		memset(&tmp,0,sizeof(Buffer));
		CertificateOfMembership_serialize(&tmp,&(nc->com));
		if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_COM,&tmp)) return false;
	}

	memset(&tmp,0,sizeof(Buffer));
	unsigned int i;
	for(i=0;i<nc->capabilityCount;++i)
		Capability_serialize(&tmp,false,&(nc->capabilities[i]));
	if (tmp.len>0) {
		if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_CAPABILITIES,&tmp)) return false;
	}

	memset(&tmp,0,sizeof(Buffer));
	for(i=0;i<nc->tagCount;++i)
		Tag_serialize(&tmp,false,&(nc->tags[i]));
	if (tmp.len>0) {
		if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_TAGS,&tmp)) return false;
	}

	memset(&tmp,0,sizeof(Buffer));
	for(i=0;i<nc->certificateOfOwnershipCount;++i)
		CertificateOfOwnership_serialize(&(nc->certificatesOfOwnership[i]),&tmp,false);
	if (tmp.len>0) {
		if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_CERTIFICATES_OF_OWNERSHIP,&tmp)) return false;
	}

	memset(&tmp,0,sizeof(Buffer));
	for(i=0;i<nc->specialistCount;++i)
		append_uint64(&tmp, (uint64_t)nc->specialists[i]);
	if (tmp.len>0) {
		if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_SPECIALISTS,&tmp)) return false;
	}

	memset(&tmp,0,sizeof(Buffer));
	for(i=0;i<nc->routeCount;++i) {
		InetAddress_Serialize((const InetAddress *)(&(nc->routes[i].target)),&tmp);
		InetAddress_Serialize((const InetAddress *)(&(nc->routes[i].via)),&tmp);
		append_uint16(&tmp,(uint16_t)nc->routes[i].flags);
		append_uint16(&tmp,(uint16_t)nc->routes[i].metric);
	}
	if (tmp.len>0) {
		if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_ROUTES,&tmp)) return false;
	}

	memset(&tmp,0,sizeof(Buffer));
	for(i=0;i<nc->staticIpCount;++i)
		InetAddress_Serialize(&(nc->staticIps[i]),&tmp);
	if (tmp.len>0) {
		if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_STATIC_IPS,&tmp)) return false;
	}

	if (nc->ruleCount) {
		memset(&tmp,0,sizeof(Buffer));
		Capability_serializeRules(&tmp,nc->rules,nc->ruleCount);
		if (tmp.len>0) {
			if (!Dictionary_addBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_RULES,&tmp)) return false;
		}
	}

	return true;
}



bool fromDictionary(Dictionary *d, NetworkConfig *nc)
{
	Buffer *tmp=(Buffer *)malloc(sizeof(Buffer));
	tmp->len = 0;

	nc->networkId = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_NETWORK_ID,0);
	if(nc->networkId==0) {
		printf("ERROR: get network Id failed\n");
		free(tmp);
		return false;
	}
	nc->timestamp = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_NETWORK_ID,0);
	nc->credentialTimeMaxDelta = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_CREDENTIAL_TIME_MAX_DELTA,0);
	nc->revision = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_REVISION,0);
	nc->issuedTo = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_ISSUED_TO,0);	//???
	if(nc->issuedTo==0) {
		printf("ERROR: get network issuedTo failed\n");
		free(tmp);
		return false;
	}
	nc->multicastLimit = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_MULTICAST_LIMIT,0);
	Dictionary_Get(d,ZT_NETWORKCONFIG_DICT_KEY_MTU,nc->name,ZT_DEFAULT_MTU);
	nc->mtu = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_MTU,ZT_DEFAULT_MTU);
	if(nc->mtu < 1280)
		nc->mtu =1280;
	else if (nc->mtu > ZT_MAX_MTU)
		nc->mtu = ZT_MAX_MTU;
	if(Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_VERSION,0) < 6) {
		free(tmp);
		return false;
	} else {
		nc->flags = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_FLAGS,0);
		nc->type = Dictionary_GetUI(d,ZT_NETWORKCONFIG_DICT_KEY_TYPE,(uint64_t)ZT_NETWORK_TYPE_PRIVATE);

		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_COM,tmp))
			CertificateOfMembership_deserialize(tmp,0,&nc->com);

		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_CAPABILITIES,tmp)) {
			unsigned int p = 0;
			while (p < tmp->len) {
				Capability cap;
				p += Capability_deserialize(tmp,p,&cap);
				nc->capabilities[nc->capabilityCount++] = cap;
			}
			qsort(&nc->capabilities[0],nc->capabilityCount,sizeof(Capability),Capability_compare);
		}

		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_TAGS,tmp)) {
			unsigned int p = 0;
			while (p < tmp->len) {
				Tag tag;
				p += Tag_deserialize(tmp,p,&tag);
				nc->tags[nc->tagCount++] = tag;
			}
			qsort(&nc->tags[0],nc->tagCount,sizeof(Tag),Tag_compare);
		}


		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_CERTIFICATES_OF_OWNERSHIP,tmp)) {
			unsigned int p = 0;
			while (p < tmp->len) {
				if (nc->certificateOfOwnershipCount < ZT_MAX_CERTIFICATES_OF_OWNERSHIP)
					p += CertificateOfOwnership_deserialize(tmp,p,&nc->certificatesOfOwnership[nc->certificateOfOwnershipCount++]);
				else {
					CertificateOfOwnership coo;
					p += CertificateOfOwnership_deserialize(tmp,p,&coo);
				}
			}
		}

		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_SPECIALISTS,tmp)) {
			unsigned int p = 0;
			while((p + 8) <= tmp->len) {
				if(nc->specialistCount < ZT_MAX_NETWORK_SPECIALISTS)
					nc->specialists[nc->specialistCount++] = Utils_ntoh_u64(*(uint64_t *)&tmp->b[p]);
				p += 8;
			}
		}

		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_ROUTES,tmp)) {
			unsigned int p = 0;
			while ((p < tmp->len)&&(nc->routeCount < ZT_MAX_NETWORK_ROUTES)) {
				p += InetAddress_Deserialize((InetAddress *)&(nc->routes[nc->routeCount].target), tmp->b,p);
				p += InetAddress_Deserialize((InetAddress *)&(nc->routes[nc->routeCount].via), tmp->b,p);
				nc->routes[nc->routeCount].flags = ntohs(*(uint16_t *)&tmp->b[p]);
				p += 2;
				nc->routes[nc->routeCount].metric = ntohs(*(uint16_t *)&tmp->b[p]);
				p += 2;
				++nc->routeCount;
			}
		}

		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_STATIC_IPS,tmp)) {
			unsigned int p = 0;
			while((p < tmp->len) && (nc->staticIpCount < ZT_MAX_ZT_ASSIGNED_ADDRESSES)) {
				InetAddress_Deserialize(&(nc->staticIps[nc->staticIpCount++]), tmp->b, p);
			}
				
		}

		if(Dictionary_GetToBuffer(d,ZT_NETWORKCONFIG_DICT_KEY_RULES,tmp)) {
			nc->routeCount = 0;
			unsigned int p = 0;
			Capability_deserializeRules(tmp, &p, nc->rules, &nc->ruleCount, ZT_MAX_NETWORK_RULES);
		}

		free(tmp);
		return true;
	}

	return false;
}

