#ifndef _ZT_WORLD_H
#define _ZT_WORLD_H

#include "list.h"
#include "InetAddress.h"
#include "Identity.h"

#define ZT_WORLD_MAX_ROOTS 4


enum Type
{
	TYPE_NULL = 0,
	TYPE_PLANET = 1, // Planets, of which there is currently one (Earth)
	TYPE_MOON = 127  // Moons, which are user-created and many
};


/**
 * Maximum number of stable endpoints per root (sanity limit, okay to increase)
 */
#define ZT_WORLD_MAX_STABLE_ENDPOINTS_PER_ROOT 32

#define ZT_WORLD_MAX_ROOTS 4

/**
 * Upstream server definition in world/moon
 */
typedef struct _root{
	Identity identity;
	InetAddrList stableEndpoints;
}Root;

typedef struct _RootsList{
	struct list_head list;
	Root root;
}Roots;

typedef struct _world{
	/**
	 * World type -- do not change IDs
	 */
	uint64_t id;
	uint64_t ts;
	enum Type type;
	unsigned char updatesMustBeSignedBy[64];		//C25519 Public key
	unsigned char signature[96];			//signature
	Roots roots;		//roots list
}World;


#endif

