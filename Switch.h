#ifndef _ZT_SWITCH_H
#define _ZT_SWITCH_H

#include "list.h"
#include "Address.h"
#include "Constants.h"
#include "Buffer.h"
#include "RuntimeEnvironment.h"
#include "Utils.h"

// Outstanding WHOIS requests and how many retries they've undergone
typedef struct _WhoisRequest
{
	uint64_t lastSent;
	Address peersConsulted[ZT_MAX_WHOIS_RETRIES]; // by retry
	unsigned int retries; // 0..ZT_MAX_WHOIS_RETRIES
}WhoisRequest;

typedef struct _outstandingWhoisRequests{
	struct list_head list;
	Address addr;	//destination ZT Address
	WhoisRequest whoisReq;
}outstandingWhoisRequests;

typedef struct _lastUniteAttempt{
	struct list_head list;
	uint64_t ts;
	Address big;
	Address little;
}LastUniteAttempt;

void Switch_Init();
void Switch_requestWhois(const Address addr);
bool Switch_send(Buffer *packet, bool encrypt);
unsigned long Switch_doTimerTasks(uint64_t now);
bool Switch_trySend(Buffer *buf, bool flag);
bool Switch_shouldUnite(const uint64_t now,const Address source,const Address destination);

#endif
