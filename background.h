#ifndef _ZT_BACKGROUND_H
#define  _ZT_BACKGROUND_H

#include<stdio.h>
#include"Utils.h"
#include"InetAddress.h"
#include"ZeroTierOne.h"

enum ZT_ResultCode  processBackgroundTasks(void *tptr,uint64_t now,volatile uint64_t *nextBackgroundTaskDeadline);


#endif
