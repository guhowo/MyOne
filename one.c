#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <netdb.h>  

#include "background.h"
#include "Utils.h"
#include "Identity.h"
#include "Packet.h"
#include "Address.h"
#include "avl_local.h"
#include "RuntimeEnvironment.h"
#include "Topology.h"
#include "IncomingPacket.h"
#include "Path.h"
#include "Buffer.h"

const int port = 4443;
RuntimeEnvironment *RR = NULL;
char * identity_secret = "61a7181461:0:5e5fb8e1b55867d50c7909a70df84fdb8f326321efb55de8da967adbde120b67941e0ab3c69cf382e76669536f3de3b3207e3b2c714aaf1a27cb3efb6ed12264:351e038c869ce2edf86fa5db160591ebc361ad55954e76d44e8bd03bdc3a1793334a03ec094d6a5661bbfd84a88ed630c3738a3ab79f49b8b2bf42892bad0678";
int udp_sockd;


void myPoll(unsigned long timeout, int sockd, struct sockaddr_in addr)
{
	//char buf[131072];
	Buffer buf;
	Buffer_Init(&buf);
	struct timeval tv;
	fd_set rfds;
	struct sockaddr_storage ss;
	struct sockaddr_in localAddress;
	localAddress.sin_family = AF_INET;
	localAddress.sin_port = htons(port);
	localAddress.sin_addr.s_addr = inet_addr("119.23.237.36");
	
	FD_SET(sockd, &rfds);
	tv.tv_sec = (long)(timeout / 1000);
	tv.tv_usec = (long)((timeout % 1000) * 1000);
	if (select((int)sockd + 1, &rfds, NULL, NULL,(timeout > 0) ? &tv : (struct timeval *)0) <= 0)
		return;

	if(FD_ISSET(sockd, &rfds)) {
		for(;;) {
			memset(&ss,0,sizeof(ss));
			int slen = sizeof(ss);
			long n = (long)recvfrom(sockd, buf.b, sizeof(buf.b), 0,  (struct sockaddr *)&ss, &slen);
			if(n > 0) {
				buf.len = (unsigned int)n;
				phyOnDatagram(udp_sockd,(const struct sockaddr *)&localAddress,(const struct sockaddr *)&ss,&buf);
			}
			else 	
				break;
		}
	}
	return;
}

int Address_Compare(void *insert, void *node){
	Address *i, *n;
	i = (Address *)insert;
	n = (Address *)node;

	return memcmp(i,n,8);
}

void init(uint64_t _now){
	RR = (RuntimeEnvironment *)malloc(sizeof(RuntimeEnvironment));
	if(!RR){
		printf("alloc RR failed\r\n");
	}
		
	RR->addrTree = avl_tree_nodup(Address_Compare);
	RR->pathsTree = avl_tree_nodup(Path_Compare);
	
	if(!Identity_FromString(identity_secret, &(RR->identity))){
		printf("read id failed\n");
		exit -1;
	}

	Topology_Init();
}


int main(int argc,char **argv)
{
	uint64_t _now, dl;
	volatile uint64_t nextBackgroundTaskDeadline;
	struct sockaddr_in address; 

	init(_now);
	memset(&address, 0, sizeof(address));
	address.sin_family=AF_INET;  
	address.sin_addr.s_addr=htonl(INADDR_ANY); 
	address.sin_port=htons(port);
		
	udp_sockd=socket(AF_INET,SOCK_DGRAM,0); 	// create a UDP socket
	bind(udp_sockd, (struct sockaddr *)&address, sizeof(address));	
	fcntl(udp_sockd,F_SETFL,O_NONBLOCK);	
	
	for(;;)
	{
		_now = now();
		// Deadline for the next background task service function

		nextBackgroundTaskDeadline = 0;
		dl = nextBackgroundTaskDeadline;
		RR->now = _now;
		if(dl <= _now)
		{
			processBackgroundTasks((void *)0, _now,&nextBackgroundTaskDeadline);
			dl = nextBackgroundTaskDeadline;
		}
		
		const unsigned long delay = (dl > _now) ? (unsigned long)(dl - _now) : 100;
		myPoll(delay, udp_sockd, address);
	}

	return 0;
}


