#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "avl_local.h"
#include "list.h"
#include "Constants.h"
#include "Utils.h"
#include "InetAddress.h"
#include "Address.h"
#include "jsondb.h"

#define MAX_JSON_STRING 1024
#define DEFAULT_PATH "./controller.d/network"

typedef struct{
	uint64_t NodeId;
	char MemberConfig[MAX_JSON_STRING];
}JsondbMembers;

typedef struct _Jsondb{	
	struct list_head list;
	uint64_t NetworkId;
	char config[MAX_JSON_STRING];
	NetworkSummaryInfo summaryInfo;
	uint64_t summaryInfoLastComputed;
	TREE *members;
}Jsondb;

static Jsondb CT;

static void _recomputeSummaryInfo(const uint64_t networkId);

int JsondbMembers_cmp(void *n, void *o)
{
	return memcmp(n, o, sizeof(uint64_t));
}

Jsondb *jsondb_new(uint64_t nwid){
	Jsondb *new_db = NULL;
	
	new_db = malloc(sizeof(Jsondb));
	if(!new_db){
		printf("error:new db failed.\n");
		return NULL;
	}
	memset(new_db, 0, sizeof(Jsondb));
	new_db->NetworkId = nwid;
	new_db->members = avl_tree_dup(JsondbMembers_cmp);
	list_add_tail(&new_db->list, &CT.list);
	return new_db;
}

int jsondb_read_member(const char *path, Jsondb * m)
{
	DIR *pDir = NULL;
	struct dirent * ent = NULL;
	JsondbMembers *member = NULL;
	char tmpPath[64];
	const char *p;
	json_object *newObject = NULL;
	
	pDir = opendir(path);
	if(!pDir){
		printf("Jsondb:open dir %s failed\n", path);
		return -1;
	}
	ent = readdir(pDir);
	while(ent){
		//file: must be member.json
		if(ent->d_type == DT_REG){
			sprintf(tmpPath, "%s/%s", path, ent->d_name);
			newObject = json_object_from_file(tmpPath);
			if(!newObject){
				printf("error: read %s failed\n", tmpPath);
				closedir(pDir);
				return -1;
			}
			p = json_object_get_string(json_object_object_get(newObject, "nwid"));
			if(Utils_hexStrToU64(p) == m->NetworkId){
				p = json_object_get_string(json_object_object_get(newObject, "id"));
				member = malloc(sizeof(JsondbMembers));
				if(!member){
					printf("error: malloc member failed\n");
					closedir(pDir);
					return -1;
				}
				member->NodeId = Utils_hexStrToU64(p);
				strcpy(member->MemberConfig, json_object_to_json_string(newObject));
				avl_insert(m->members, member);
			}else{
				//networkid not match ignore
			}
			json_object_put(newObject);
		}
		ent = readdir(pDir);
	}
	closedir(pDir);
	
	return 0;
}

int jsondb_read_networkId(const char *path)
{
	DIR *pDir = NULL;
	struct dirent * ent = NULL;
	char tmpPath[64];
	json_object *newObject = NULL;
	const char *p = NULL;
	Jsondb *new_db = NULL;
	int ret = 0;
	
	pDir = opendir(path);
	if(!pDir){
		printf("Jsondb:open dir %s failed\n", path);
		return -1;
	}

	ent = readdir(pDir);
	while(ent){
		//file: must be networkid.json
		if(ent->d_type == DT_REG){
			sprintf(tmpPath, "%s/%s", path, ent->d_name);
			newObject = json_object_from_file(tmpPath);
			if(!newObject){
				printf("error: read %s failed\n", tmpPath);
				closedir(pDir);
				return -1;
			}
			//get nwid
			p = json_object_get_string(json_object_object_get(newObject, "id"));
			if(!p){
				printf("get networkid NULL,ignore\n");
				ent = readdir(pDir);
				continue;
			}
			new_db = jsondb_new(Utils_hexStrToU64(p));
			if(!new_db){
				return -1;
			}
			strcpy(new_db->config, json_object_to_json_string(newObject));
			json_object_put(newObject);
			sprintf(tmpPath, "%s/%s/member", DEFAULT_PATH, p);
			ret |= jsondb_read_member(tmpPath, new_db);
		}else{
			//read json first 
			//dir must be member 
		}

		ent = readdir(pDir);
	}
	closedir(pDir);

	return ret;
}

//return 0: success,else flase
int Jsondb_load(void){
	int ret = 0;
	
	{
		//ignore http get config function
	}
	INIT_LIST_HEAD(&CT.list);
	ret |= jsondb_read_networkId(DEFAULT_PATH);

	return ret;
}

Jsondb * jsondb_find(const uint64_t networkId)
{
	Jsondb *pdb = NULL, *pos;
	

	list_for_each_entry(pos, &CT.list, list){
		if(pos->NetworkId == networkId){
			pdb = pos;
			break;
		}
	}
	return pdb;
}

JsondbMembers * jsondbMember_find(Jsondb *pdb, const uint64_t nodeId)
{
	uint64_t n = nodeId;
	
	return (JsondbMembers *)avl_locate(pdb->members, &n);
}

JsondbMembers * jsondbMember_remove(Jsondb *pdb, const uint64_t nodeId)
{
	uint64_t n = nodeId;
	return (JsondbMembers *)avl_remove(pdb->members, &n);
}


bool Jsondb_hasNetwork(const uint64_t networkId)
{
	return jsondb_find(networkId) == NULL ? false:true;
}

bool Jsondb_getNetwork(const uint64_t networkId, json_object *config)
{
	Jsondb *pdb = NULL;
	
	pdb = jsondb_find(networkId);
	if(!pdb){
		return false;
	}
	config = json_tokener_parse(pdb->config);
	return true;
}

bool Jsondb_getNetworkSummaryInfo(const uint64_t networkId,NetworkSummaryInfo *ns)
{
	Jsondb *pdb = NULL;
	
	pdb = jsondb_find(networkId);
	if(!pdb){
		return false;
	}
	
	memcpy(ns, &pdb->summaryInfo, sizeof(NetworkSummaryInfo));
	return true;
}


/**
 * @return Bit mask: 0 == none, 1 == network only, 3 == network and member
 */
int Jsondb_getNetworkAndMember(const uint64_t networkId,const uint64_t nodeId, json_object **networkConfig, json_object **memberConfig,NetworkSummaryInfo *ns)
{
	Jsondb *pdb = NULL;
	JsondbMembers *pjm = NULL;

	pdb = jsondb_find(networkId);
	if(!pdb){
		return 0;
	}

	pjm = jsondbMember_find(pdb, nodeId);
	if(!pjm){
		return 1;
	}
	*networkConfig = json_tokener_parse(pdb->config);
	*memberConfig = json_tokener_parse(pjm->MemberConfig);
	memcpy(ns, &pdb->summaryInfo, sizeof(NetworkSummaryInfo));
	
	return 3;
}

bool Jsondb_getNetworkMember(const uint64_t networkId,const uint64_t nodeId, json_object *memberConfig){
	Jsondb *pdb = NULL;
	JsondbMembers *pjm = NULL;

	pdb = jsondb_find(networkId);
	if(!pdb){
		return false;
	}

	pjm = jsondbMember_find(pdb, nodeId);
	if(!pjm){
		return false;
	}
	
	memberConfig = json_tokener_parse(pjm->MemberConfig);
	return true;
}

bool writeFile(const char *path,const void *buf,unsigned int len)
{
	FILE *f = fopen(path,"wb");
	if (f) {
		if ((long)fwrite(buf,1,len,f) != (long)len) {
			fclose(f);
			return false;
		} else {
			fclose(f);
			return true;
		}
	}
	return false;
}

void Jsondb_saveNetwork(const uint64_t networkId, json_object *networkConfig)
{
	const char *p = NULL;
	char n[64];
	Jsondb *pdb = NULL;
	JsondbMembers *pjm = NULL;
	
	snprintf(n,sizeof(n),"%s/%.16llx.json", DEFAULT_PATH,(unsigned long long)networkId);
	p = json_object_to_json_string(networkConfig);
	writeFile(n, p, strlen(p)+1);

	pdb = jsondb_find(networkId);
	if(!pdb){
		pdb = jsondb_new(networkId);
	}
	strcpy(pdb->config, json_object_to_json_string(networkConfig));
	_recomputeSummaryInfo(networkId);
	return;
}

void Jsondb_saveNetworkMember(const uint64_t networkId,const uint64_t nodeId, json_object *memberConfig)
{
	char n[256];
	const char *p = NULL;
	Jsondb *pdb = NULL;
	JsondbMembers *pjm = NULL;
	
	snprintf(n,sizeof(n),"%s/%.16llx/member/%.10llx.json", DEFAULT_PATH, (unsigned long long)networkId,(unsigned long long)nodeId);
	p = json_object_to_json_string(memberConfig);
	writeFile(n, p, strlen(p)+1);

	pdb = jsondb_find(networkId);
	if(!pdb){
		pdb = jsondb_new(networkId);
	}

	pjm = jsondbMember_find(pdb, nodeId);
	if(!pjm){
		pjm = malloc(sizeof(JsondbMembers));
		if(!pjm){
			printf("error: malloc member failed\n");
			return;
		}
		pjm->NodeId = nodeId;
		avl_insert(pdb->members, pjm);
	}
	strcpy(pjm->MemberConfig, json_object_to_json_string(memberConfig));
	
	_recomputeSummaryInfo(networkId);
	return;
}

void Jsondb_eraseNetworkMember(const uint64_t networkId,const uint64_t nodeId,bool recomputeSummaryInfo)
{
	char n[256];	
	Jsondb *pdb = NULL;
	JsondbMembers *pjm = NULL;
	
	snprintf(n,sizeof(n),"rm -rf %s/%.16llx/member/%.10llx.json",DEFAULT_PATH,(unsigned long long)networkId,(unsigned long long)nodeId);
	(void)system(n);

	pdb = jsondb_find(networkId);
	if(!pdb){
		return;
	}
	pjm = jsondbMember_remove(pdb, nodeId);
	if(!pjm){
		return;
	}
	free(pjm);
	
	if (recomputeSummaryInfo)
		_recomputeSummaryInfo(networkId);
	return;
}

void Jsondb_eraseNetwork(const uint64_t networkId)
{
	uint64_t nid[1024];
	int i = 0, j;
	Jsondb *pdb = NULL;
	JsondbMembers *pjm = NULL;
	char n[256];

	pdb = jsondb_find(networkId);
	if(!pdb){
		return;
	}
	
	avl_for_each_safe(pjm, pdb->members){
		nid[i++] = pjm->NodeId;
	}
	for(j = 0; j < i; j++){
		Jsondb_eraseNetworkMember(networkId, nid[j], false);
	}

	snprintf(n,sizeof(n),"%s/%.16llx.json", DEFAULT_PATH, (unsigned long long)networkId);
	system(n);

	list_del(&pdb->list);
	free(pdb);
}
//json boolean: true/flase(case sensitive)
static void _recomputeSummaryInfo(const uint64_t networkId)
{
	Jsondb *pdb = NULL;
	JsondbMembers *pjm = NULL;
	NetworkSummaryInfo *ns = NULL;
	json_object * mcfg = NULL;
	const uint64_t Now = now();
	int i, lt;
	const char *p = NULL;
	InetAddrList *pil = NULL;

	pdb = jsondb_find(networkId);
	if(!pdb){
		return;
	}
	
	ns = &pdb->summaryInfo;
	memset(ns, 0, sizeof(NetworkSummaryInfo));

	avl_for_each_safe(pjm, pdb->members){
		mcfg = json_tokener_parse(pjm->MemberConfig);
		if(json_object_get_boolean(json_object_object_get(mcfg, "authorized"))){
			++ns->authorizedMemberCount;
			json_object *mlog = json_object_object_get(mcfg, "recentLog");
			if((json_type_array == json_object_get_type(mlog))
				&&(json_object_array_length(mlog) > 0)){
				json_object *mlog1 = json_object_array_get_idx(mlog, 0);
				if(json_type_array == json_object_get_type(mlog1)){
					if((Now - json_object_get_int(json_object_object_get(mlog1, "ts"))) < (ZT_NETWORK_AUTOCONF_DELAY * 2)){
						++ns->activeMemberCount;
					}
				}
			}
			if(json_object_get_boolean(json_object_object_get(mcfg, "activeBridge"))){
				ns->activeBridges[ns->AddressNum++] = pjm->NodeId & 0xffffffffffULL;
			}
			json_object *mips = json_object_object_get(mcfg, "ipAssignments");
			if(json_type_array == json_object_get_type(mips)){
				for(i = 0; i < json_object_array_length(mips); i++){
					p = json_object_get_string(json_object_array_get_idx(mips, i));
					pil = malloc(sizeof(InetAddrList));
					//failed not deal
					InetAddress_fromString(p, &pil->InetAddr);
					list_add(&pil->list, &(ns->allocatedIps.list));
				}
			}
		}else{
			lt = json_object_get_int(json_object_object_get(mcfg, "lastDeauthorizedTime"));
			ns->mostRecentDeauthTime = ns->mostRecentDeauthTime > lt ? ns->mostRecentDeauthTime : lt;
		}
		++ns->totalMemberCount;
	}
	pdb->summaryInfoLastComputed = Now;

	return;
}

