#ifndef _ZT_RUNTIMEENVIRONMENT_H
#define _ZT_RUNTIMEENVIRONMENT_H

#include "Identity.h"
#include "Topology.h"
#include "avl_local.h"

typedef struct _RuntimeEnvironment{
	Identity identity;
	Topology *pTopology;	
	TREE *addrTree;
	TREE *pathsTree;
	uint64_t now;
}RuntimeEnvironment;

#endif
