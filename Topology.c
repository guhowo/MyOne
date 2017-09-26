#include "Topology.h"
#include "InetAddress.h"
#include <string.h>
#include <stdio.h>
#include "RuntimeEnvironment.h"
#include "Utils.h"
#include "Identity.h"
#include "C25519.h"

#define ZT_DEFAULT_WORLD_LENGTH 257 
static const unsigned char ZT_DEFAULT_WORLD[ZT_DEFAULT_WORLD_LENGTH] = {0x01,0x00,0x00,0x00,0x61,0xa7,0x18,0x14,0x61,0x00,0x00,0x01,0x5e,0x74,0xd7,0x31,0xf5,0x60,0x40,0xc8,0x51,0x4d,0x36,0x35,0x0c,0x26,0x0b,0x82,0x02,0xb2,0x57,0x07,0xcf,0x26,0x19,0xcc,0x2a,0x9a,0xc1,0x4e,0x4d,0xc8,0x52,0xdb,0xa2,0xa9,0x7b,0x4c,0x2b,0x0f,0xcd,0x33,0x06,0xed,0x82,0x81,0xed,0xff,0x59,0xfe,0x57,0xee,0x6d,0xbb,0x82,0xe0,0xae,0x71,0x99,0x0e,0xae,0x68,0x6c,0xb3,0xfc,0x90,0x63,0x57,0x43,0x03,0x5b,0x8b,0xe6,0x82,0xc5,0xe3,0x4a,0x6a,0x9a,0xf4,0xc0,0xc4,0x18,0x8f,0xed,0x4b,0xfb,0xfa,0xf8,0xa8,0x53,0x85,0x51,0xfe,0x28,0x95,0x68,0x0b,0xab,0x26,0x8a,0x4c,0x5a,0xe3,0x43,0x64,0x15,0xb7,0xaf,0x7d,0x38,0x1b,0xcd,0xcd,0x36,0xe8,0x5c,0x14,0x10,0x22,0xc7,0x6f,0xef,0x14,0xb7,0x8a,0x30,0x2e,0x37,0x10,0xfc,0x0c,0x49,0x1b,0x04,0x4d,0x27,0xe5,0x00,0x58,0x42,0x66,0x5f,0x77,0x41,0x9d,0xf8,0xb6,0xd4,0x15,0x5f,0xa6,0x57,0x98,0x09,0xff,0xcd,0x2c,0xc2,0x50,0xc9,0xab,0x99,0xc8,0xa4,0xd2,0x31,0x01,0x61,0xa7,0x18,0x14,0x61,0x00,0x5e,0x5f,0xb8,0xe1,0xb5,0x58,0x67,0xd5,0x0c,0x79,0x09,0xa7,0x0d,0xf8,0x4f,0xdb,0x8f,0x32,0x63,0x21,0xef,0xb5,0x5d,0xe8,0xda,0x96,0x7a,0xdb,0xde,0x12,0x0b,0x67,0x94,0x1e,0x0a,0xb3,0xc6,0x9c,0xf3,0x82,0xe7,0x66,0x69,0x53,0x6f,0x3d,0xe3,0xb3,0x20,0x7e,0x3b,0x2c,0x71,0x4a,0xaf,0x1a,0x27,0xcb,0x3e,0xfb,0x6e,0xd1,0x22,0x64,0x00,0x01,0x04,0x77,0x17,0xed,0x24,0x11,0x5b};

static CertificateOfRepresentation CRepresentation;
Roots *pRoots = NULL;
Topology topy; 

static upstreamAddress *pupstreams = &(topy.upstreamAddresses);
extern RuntimeEnvironment *RR;


bool findUpstream(Address addr)
{
    upstreamAddress *tmp;
    list_for_each_entry(tmp, &pupstreams->list, list) {
        if(tmp->addr == addr)
            return true;
    }
    return false;
}


bool findPeer(Address addr)
{
    return (avl_locate(RR->addrTree, (void *)&addr) != NULL);
}

static bool findStableEndpoints(InetAddress *addr, InetAddrList *iAddrlist)
{
    InetAddrList *tmp;
    list_for_each_entry(tmp, &iAddrlist->list, list) {
        if(memcmp(&tmp->InetAddr.address, &addr->address, sizeof(InetAddress)) == 0) {
            return true;
        }
    }
    return false;
}

static void certificate_serialize(Buffer * buf, bool forSign){
    unsigned int i = 0;
    if (forSign){
        append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
    }

    append_uint64(buf, (uint64_t)CRepresentation._timestamp);
    append_uint16(buf, (uint16_t)CRepresentation.repCount);
    for(i = 0;i < CRepresentation.repCount; ++i){
        Address_AppendTo(buf, CRepresentation.reps[i]);
    }

    if (!forSign) {
        append(buf, (uint8_t)1); // 1 == Ed25519 signature
        append_uint16(buf, (uint16_t)ZT_C25519_SIGNATURE_LEN);
        append_databylen(buf, CRepresentation._signature,ZT_C25519_SIGNATURE_LEN);
    }

    append_uint16(buf, (uint16_t)0); // size of any additional fields, currently 0

    if (forSign){
        append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
    }
}

unsigned int Certificate_Deserialize(CertificateOfRepresentation *cor,const unsigned char *data, unsigned int len,unsigned int startAt)
{
    memset(&cor,0,sizeof(cor));

    unsigned int p = startAt;

    cor->_timestamp = Utils_ntoh_u64(((uint64_t *)data)[p]); 
    p += 8;
    const unsigned int rc = (unsigned int)ntohs(((uint16_t *)data)[p]);
    p += 2;
    unsigned int i;
    for(i=0;i<rc;++i) {
        if (i < ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES)
            Address_SetTo(data,ZT_ADDRESS_LENGTH,&cor->reps[i]);
        p += ZT_ADDRESS_LENGTH;
    }
    cor->repCount = (rc > ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES) ? ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES : rc;

    if (data[p++] == 1) {
        if (ntohs(((uint16_t *)data)[p]) == ZT_C25519_SIGNATURE_LEN) {
            p += 2;
            memcpy(cor->_signature,&data[p],ZT_C25519_SIGNATURE_LEN);
            p += ZT_C25519_SIGNATURE_LEN;
        } else {
            printf("invalid signature\n");
            exit(1);
        }
    } else {
        p += 2 + ntohs(((uint16_t *)data)[p]);
    }

    p += 2 + ntohs(((uint16_t *)data)[p]);
    if (p > len) {
        printf("extended field overflow\n");
        exit(1);
    }

    return (p - startAt);
}

void Certificate_sign(const Identity *myIdentity,const uint64_t ts)
{
    Buffer tmp;
    Buffer_Init(&tmp);
    CRepresentation._timestamp = ts;
    certificate_serialize(&tmp,true);
    C25519_sign4(CRepresentation._signature, myIdentity->_privateKey, myIdentity->_publicKey, tmp.b, tmp.len);
}

void Topology_Serialize(Buffer * buf, bool forSign)
{
    World *pTmpWorld = &(RR->pTopology->planet);
    Roots *pTmpRoots = NULL;
    InetAddrList *pTmpInetAddr = NULL;
    unsigned char rootNum = 0;
    unsigned char endpointNum = 0;
    int posRoot = 0;
    int posEndpoint = 0;
    
    if (forSign){
        append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
    }

    append(buf, (uint8_t)pTmpWorld->type);
    append_uint64(buf, (uint64_t)pTmpWorld->id);
    append_uint64(buf, (uint64_t)pTmpWorld->ts);
    append_databylen(buf,  (void *)pTmpWorld->updatesMustBeSignedBy, ZT_C25519_PUBLIC_KEY_LEN);
    if (!forSign){
        append_databylen(buf, (void *)pTmpWorld->signature, ZT_C25519_SIGNATURE_LEN);
    }

    posRoot = buf->len++;
    
    list_for_each_entry(pTmpRoots, &(pTmpWorld->roots.list), list){
        rootNum++;
        Identity_Serialize(&(pTmpRoots->root.identity), buf, false);
        posEndpoint = buf->len++;
        list_for_each_entry(pTmpInetAddr, &(pTmpRoots->root.stableEndpoints.list), list){
            endpointNum++;
            InetAddress_Serialize(&(pTmpInetAddr->InetAddr), buf);
        }
        buf->b[posEndpoint] = endpointNum;
    }
    buf->b[posRoot] = (uint8_t)rootNum;
    if (pTmpWorld->type == TYPE_MOON){
        append_uint16(buf, 0);// no attached dictionary (for future use)
    } 

    if (forSign){
        append_uint64(buf, (uint64_t)0x7f7f7f7f7f7f7f7fULL);
    }
}

unsigned int Topology_Deserialize(World *newWorld, Roots *newRootHead, const unsigned char *b,unsigned int startAt)
{
    unsigned int p = startAt;

    switch((enum Type)b[p++]) {
        case TYPE_NULL: newWorld->type = TYPE_NULL; break; // shouldn't ever really happen in serialized data but it's not invalid
        case TYPE_PLANET: newWorld->type = TYPE_PLANET; break;
        case TYPE_MOON: newWorld->type = TYPE_MOON; break;
        default: printf("invalid world type");    exit(1);
    }

    newWorld->id = Utils_ntoh_u64(*(uint64_t *)&b[p]); //*((uint64_t *)(b+p))
    p += 8;
    newWorld->ts = Utils_ntoh_u64(*(uint64_t *)&b[p]);     
    p += 8;
    memcpy(newWorld->updatesMustBeSignedBy, b+p, sizeof(newWorld->updatesMustBeSignedBy)); 
    p += sizeof(newWorld->updatesMustBeSignedBy);
    memcpy(newWorld->signature, b+p, sizeof(newWorld->signature)); 
    p += sizeof(newWorld->signature);
    const unsigned int numRoots = (unsigned int)b[p++];
    if (numRoots > ZT_WORLD_MAX_ROOTS) {
        printf("too many roots in World");    
        exit(2);
    }
    
    unsigned int k;
    for(k=0;k<numRoots;++k) {
        Roots *r = (Roots *)malloc(sizeof(Roots));
        p += Identity_Deserialize(&(r->root.identity),b,p);    //initialize root->identity
        unsigned int numStableEndpoints = b[p++];
        if (numStableEndpoints > ZT_WORLD_MAX_STABLE_ENDPOINTS_PER_ROOT) {
            printf("too many stable endpoints in World/Root\n");
            exit(2);
        }
        unsigned int kk;
        INIT_LIST_HEAD(&r->root.stableEndpoints.list);         //initialize roots list
        for(kk=0;kk<numStableEndpoints;++kk) {
            InetAddrList *iAddr = (InetAddrList *)malloc(sizeof(InetAddrList));
            p += InetAddress_Deserialize(&iAddr->InetAddr, b, p);
            r->root.stableEndpoints.InetAddr = iAddr->InetAddr;
            list_add_tail(&(iAddr->list), &(r->root.stableEndpoints.list));
        }
        list_add_tail(&(r->list), &(newRootHead->list));
    }
    if (newWorld->type == TYPE_MOON)
        p += (unsigned int)ntohs(*(uint16_t*)&b[p]) + 2;

    return (p - startAt);
}

void memoizeUpstreams(World *world)
{
    Roots *proots = &world->roots;
    Roots *tmp;
    upstreamAddress *tmpStream = NULL;
    
    list_for_each_entry(tmp, &proots->list, list) {
        if(Identity_IsEqual(&tmp->root.identity, &RR->identity)) {
            topy.amRoot = true;
        } else if(!findUpstream(tmp->root.identity._address)) {
            tmpStream = (upstreamAddress *)malloc(sizeof(upstreamAddress));
            tmpStream->addr = tmp->root.identity._address; 
            list_add_tail(&tmpStream->list, &pupstreams->list);
            
            if(!findPeer(tmp->root.identity._address)) {
                PeerNode *tmpPeer = (PeerNode *)malloc(sizeof(PeerNode));
                memset(tmpPeer, 0, sizeof(PeerNode));
                tmpPeer->address = tmp->root.identity._address;
                Peer_Init(&tmpPeer->peer, &(tmp->root.identity));
                memcpy(&tmpPeer->id, &tmpPeer->peer.id, sizeof(Identity));
                tmpPeer->pInetAddress = &tmp->root.stableEndpoints; //only for read,do not write
                avl_insert(RR->addrTree, (void *)tmpPeer);
            }
        }
    }

    /**
    ***moons to upstreams
    **/

    list_for_each_entry(tmpStream, &pupstreams->list, list) {
        if (CRepresentation.repCount < ZT_CERTIFICATEOFREPRESENTATION_MAX_ADDRESSES) {
            CRepresentation.reps[CRepresentation.repCount++] = tmpStream->addr;
            continue;
        }
        break;
    }
    memset(&CRepresentation, 0, sizeof(CRepresentation));
    Certificate_sign(&RR->identity,now());        ////when get the _now
    
}


bool Topology_AddWorld(World *newWorld, bool alwaysAcceptNew)
{
    if ((newWorld->type != TYPE_PLANET)&&(newWorld->type != TYPE_MOON))
            return false;

    memoizeUpstreams(newWorld);
    
    return true;
}

Peer *Topology_AddPeer(Peer *peer)
{
    PeerNode *np = NULL;
    np = (PeerNode *)avl_locate(RR->addrTree, &peer->id._address);
    
    if(!np) {
        np = (PeerNode *)malloc(sizeof(PeerNode));
        memset(np, 0, sizeof(PeerNode));
        memcpy(&np->peer, peer, sizeof(Peer));
        memcpy(&np->address, &peer->id._address, sizeof(Address));
        memcpy(&np->id, &peer->id, sizeof(peer->id));
        avl_insert(RR->addrTree,(void *)np);
    }

    //save identity to local db

    return &np->peer;
}

void Topology_Init(void)
{    
    RR->pTopology = &topy;
    memset(&topy, 0, sizeof(topy));
    pRoots = &(topy.planet.roots);
    INIT_LIST_HEAD(&pRoots->list);         //initialize roots list
    
    Topology_Deserialize(&(topy.planet), pRoots, ZT_DEFAULT_WORLD, 0);
    INIT_LIST_HEAD(&(pupstreams->list));
    
    Topology_AddWorld(&(topy.planet), false);
}

void Topology_AppendCor(Buffer * buf){
        certificate_serialize(buf, false);
}

Path *Topology_GetPath(const InetAddress *local, const InetAddress *remote){
    Path *p = NULL;
    PathKey key;

    memcpy(&(key.r), remote, sizeof(InetAddress));
    memcpy(&(key.l), local, sizeof(InetAddress));

    p = avl_locate(RR->pathsTree, (void *)&key);
    if(!p){
        p = malloc(sizeof(Path));
        memcpy(&(p->addr), remote, sizeof(InetAddress));
        memcpy(&(p->localAddress), local, sizeof(InetAddress));
        avl_insert(RR->pathsTree, (void *)p);
    }
    
    return p;
}


bool Topology_IsInUpstreams(const Address *addr)
{    
    if (findUpstream(*addr))
        return true;
    return false;
}

PeerNode *Topology_GetPeerNode(Address addr){
    PeerNode * p = NULL;
    p = avl_locate(RR->addrTree, (void *)&addr);
    if(!p){
        printf("get peernode by address failed\n");    
        return NULL;
    }
    return p;

}

Identity *Topology_getIdentity(Address zta)
{
    if(RR->identity._address==zta) {
        return &RR->identity;
    } else {
        Peer *ap=Peer_GotByAddress(zta);
        if(ap) 
            return &(ap->id);    
    }

    //return _getIdentity(tPtr,zta);
}



Peer *Topology_getUpstreamPeer(const Address *avoid,unsigned int avoidCount,bool strictAvoid)
{
/*++++++++++need to do++++++++++++++++*/
    upstreamAddress *tmpStream = NULL;
    unsigned int i;
    Peer *p=NULL;
    list_for_each_entry(tmpStream, &pupstreams->list, list) {
        p=Peer_GotByAddress(tmpStream->addr);
        if(p) {
            bool avoiding = false;
            for(i=0;i<avoidCount;++i) {
                if (avoid[i] == p->id._address) {
                    avoiding = true;
                    break;
                }
            }
        }
    }

    return p;
}

bool Topology_isProhibitedEndpoint(const Address ztaddr,const InetAddress *ipaddr)
{
    InetAddrList *pos = NULL;
    // For roots the only permitted addresses are those defined. This adds just a little
    // bit of extra security against spoofing, replaying, etc.
    PeerNode *pnode = Topology_GetPeerNode(ztaddr);
    if(pnode){
        if(!pnode->pInetAddress){
            return false;
        }
        list_for_each_entry(pos, &(pnode->pInetAddress->list), list){
            if(InetAddress_ipsEqual(&pos->InetAddr, ipaddr)){
                return false;
            }
        }
        //no moons
        return true;
    }

    return false;
}


