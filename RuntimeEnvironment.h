#ifndef _ZT_RUNTIMEENVIRONMENT_H
#define _ZT_RUNTIMEENVIRONMENT_H

#include "Identity.h"
#include "Topology.h"
#include "avl_local.h"
#include "NetworkController.h"
#include "Multicaster.h"

typedef struct _RuntimeEnvironment{
	Identity identity;
	Topology *pTopology;	
	TREE *addrTree;
	TREE *pathsTree;
	uint64_t now;

	// This is set externally to an instance of this base class
	NetworkController *localNetworkController;
    Multicaster *mc;

}RuntimeEnvironment;

#endif
