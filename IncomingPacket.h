#ifndef _ZT_INCOMINGPACKET_H
#define _ZT_INCOMINGPACKET_H


#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <netdb.h>  
#include "Utils.h"
#include "Buffer.h"

// Bit mask for "expecting reply" hash
#define ZT_EXPECTING_REPLIES_BUCKET_MASK1 255
#define ZT_EXPECTING_REPLIES_BUCKET_MASK2 31

void phyOnDatagram(int socket,const struct sockaddr *localAddr,const struct sockaddr *from,Buffer *buf);
void expectReplyTo(const uint64_t packetId);
bool expectingReplyTo(const uint64_t packetId);

#endif

