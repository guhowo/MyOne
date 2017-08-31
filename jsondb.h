#ifndef __JSONDB_H
#define __JSONDB_H

#include "./json/json.h"

typedef struct _NetworkSummaryInfo
{
	Address activeBridges[100];
	int AddressNum;
	InetAddrList allocatedIps;
	unsigned long authorizedMemberCount;
	unsigned long activeMemberCount;
	unsigned long totalMemberCount;
	uint64_t mostRecentDeauthTime;
}NetworkSummaryInfo;

int Jsondb_load(void);
bool Jsondb_hasNetwork(const uint64_t networkId);
bool Jsondb_getNetwork(const uint64_t networkId, json_object *config);
bool Jsondb_getNetworkSummaryInfo(const uint64_t networkId,NetworkSummaryInfo *ns);
int Jsondb_getNetworkAndMember(const uint64_t networkId,const uint64_t nodeId, json_object **networkConfig, json_object **memberConfig,NetworkSummaryInfo *ns);
bool Jsondb_getNetworkMember(const uint64_t networkId,const uint64_t nodeId, json_object *memberConfig);
void Jsondb_saveNetwork(const uint64_t networkId, json_object *networkConfig);
void Jsondb_saveNetworkMember(const uint64_t networkId,const uint64_t nodeId, json_object *memberConfig);
void Jsondb_eraseNetwork(const uint64_t networkId);
void Jsondb_eraseNetworkMember(const uint64_t networkId,const uint64_t nodeId,bool recomputeSummaryInfo);

#endif
