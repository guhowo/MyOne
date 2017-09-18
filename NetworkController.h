#ifndef ZT_EMBEDDEDNETWORKCONTROLLER_H
#define ZT_EMBEDDEDNETWORKCONTROLLER_H

#include "InetAddress.h"
#include "Dictionary.h"
#include "Identity.h"
#include "Utils.h"
#include "jsondb.h"
#include "Address.h"
#include "avl_local.h"
#include "list.h"
#include "Network.h"


enum ncErrorCode {
	NC_ERROR_NONE = 0,
	NC_ERROR_OBJECT_NOT_FOUND = 1,
	NC_ERROR_ACCESS_DENIED = 2,
	NC_ERROR_INTERNAL_SERVER_ERROR = 3
};

uint64_t prngState[2];

//controller and JSONDB
typedef struct _EmbeddedNetworkController{
	uint64_t startTime;
	//JSONDB db;
	char *path;
	Identity signingId;
	Networks ctrlr;
}NetworkController;


//Member Status
typedef struct {
	uint64_t lastRequestTime;
	int vMajor,vMinor,vRev,vProto;
	Dictionary lastRequestMetaData;
	Identity identity;
	InetAddress physicalAddr; // last known physical address
}MemberStatus;

void NetworkController_Init();
void NetworkController_Request(uint64_t nwid,const InetAddress *fromAddr,uint64_t requestPacketId,const Identity *identity,const Dictionary *metaData);
void NetworkController_InitMember(json_object *member);
void ncSendError(uint64_t nwid,uint64_t requestPacketId,const Address destination,enum ncErrorCode errorCode);
void Node_Init(void);
uint64_t prng();

#endif
