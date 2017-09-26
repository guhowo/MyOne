#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "Constants.h"
#include "Utils.h"
#include "C25519.h"
#include "SHA512.h"
#include "Identity.h"
#include "RuntimeEnvironment.h"

extern RuntimeEnvironment *RR;
#define ZT_IDENTITY_GEN_HASHCASH_FIRST_BYTE_LESS_THAN 17
#define ZT_IDENTITY_GEN_MEMORY 2097152

// A memory-hard composition of SHA-512 and Salsa20 for hashcash hashing
static void _computeMemoryHardHash(const void *publicKey,unsigned int publicKeyBytes,void *digest,void *genmem)
{
    // Digest publicKey[] to obtain initial digest
    SHA512_hash(digest,publicKey,publicKeyBytes);

    // Initialize genmem[] using Salsa20 in a CBC-like configuration since
    // ordinary Salsa20 is randomly seekable. This is good for a cipher
    // but is not what we want for sequential memory-harndess.
    memset(genmem,0,ZT_IDENTITY_GEN_MEMORY);
    Salsa20 s20;
    Salsa20_init(&s20, digest,(char *)digest + 32);
    Salsa20_crypt20(&s20,(char *)genmem,(char *)genmem,64);
    unsigned long i;
    for(i=64;i<ZT_IDENTITY_GEN_MEMORY;i+=64) {
        unsigned long k = i - 64;
        *((uint64_t *)((char *)genmem + i)) = *((uint64_t *)((char *)genmem + k));
        *((uint64_t *)((char *)genmem + i + 8)) = *((uint64_t *)((char *)genmem + k + 8));
        *((uint64_t *)((char *)genmem + i + 16)) = *((uint64_t *)((char *)genmem + k + 16));
        *((uint64_t *)((char *)genmem + i + 24)) = *((uint64_t *)((char *)genmem + k + 24));
        *((uint64_t *)((char *)genmem + i + 32)) = *((uint64_t *)((char *)genmem + k + 32));
        *((uint64_t *)((char *)genmem + i + 40)) = *((uint64_t *)((char *)genmem + k + 40));
        *((uint64_t *)((char *)genmem + i + 48)) = *((uint64_t *)((char *)genmem + k + 48));
        *((uint64_t *)((char *)genmem + i + 56)) = *((uint64_t *)((char *)genmem + k + 56));
        Salsa20_crypt20(&s20,(char *)genmem + i,(char *)genmem + i,64);
    }

    // Render final digest using genmem as a lookup table
    for(i=0;i<(ZT_IDENTITY_GEN_MEMORY / sizeof(uint64_t));) {
        unsigned long idx1 = (unsigned long)(Utils_hton_u64(((uint64_t *)genmem)[i++]) % (64 / sizeof(uint64_t)));
        unsigned long idx2 = (unsigned long)(Utils_hton_u64(((uint64_t *)genmem)[i++]) % (ZT_IDENTITY_GEN_MEMORY / sizeof(uint64_t)));
        uint64_t tmp = ((uint64_t *)genmem)[idx2];
        ((uint64_t *)genmem)[idx2] = ((uint64_t *)digest)[idx1];
        ((uint64_t *)digest)[idx1] = tmp;
        Salsa20_crypt20(&s20,digest,digest,64);
    }
}



// Hashcash generation halting condition -- halt when first byte is less than
// threshold value.
typedef struct _Identity_generate_cond
{
    unsigned char digest[64];
    char genmem[ZT_IDENTITY_GEN_MEMORY];
}Identity_generate_cond;

bool cond_operatoring(const Pair *kp, Identity_generate_cond *igc)
{    
    _computeMemoryHardHash(kp->pub, sizeof(kp->pub), igc->digest, igc->genmem);
    return (igc->digest[0] < ZT_IDENTITY_GEN_HASHCASH_FIRST_BYTE_LESS_THAN);
}


Pair *identity_generateSatisfying(Identity_generate_cond *cond)
{
    Pair *kp;
    void *const priv = (void *)kp->priv;
    getSecureRandom(priv,(unsigned int)ZT_C25519_PRIVATE_KEY_LEN);
    C25519_calcPubED(kp); // do Ed25519 key -- bytes 32-63 of pub and priv
    do {
        ++(((uint64_t *)priv)[1]);
        --(((uint64_t *)priv)[2]);
        C25519_calcPubDH(kp); // keep regenerating bytes 0-31 until satisfied
    } while (!cond_operatoring(kp, cond));
    return kp;
}

void Identity_Generate(Identity *id)
{
    Identity_generate_cond *cond = NULL;
    memset(id, 0, sizeof(Identity));
    memset(cond, 0, sizeof(cond));

    Pair *kp = NULL;
    do {
        kp = identity_generateSatisfying(cond);
        Address_SetTo(cond->digest + 59,ZT_ADDRESS_LENGTH, &(id->_address)); // last 5 bytes are address
    } while (Address_IsReserved(id->_address));

    memcpy(id->_publicKey, kp->pub, ZT_C25519_PUBLIC_KEY_LEN);
    memcpy(id->_privateKey, kp->priv, ZT_C25519_PRIVATE_KEY_LEN);

    return;
}


void Identity_Serialize(Identity *identity, Buffer *buf, bool includePrivate)
{
    Address_AppendTo(buf, identity->_address);
    append(buf, (uint8_t)0); // C25519/Ed25519 identity type
    append_databylen(buf, identity->_publicKey,sizeof(identity->_publicKey));
    if ((identity->_privateKey != NULL)&&(includePrivate)) {
        append(buf, (unsigned char)sizeof(identity->_privateKey));
        append_databylen(buf, identity->_privateKey, (unsigned int)sizeof(identity->_privateKey));
    } else append(buf, (unsigned char)0);
    return;
}


int Identity_Deserialize(Identity *id, const unsigned char *b,unsigned int startAt)
{
    memset(id->_privateKey, 0, sizeof(id->_privateKey));
    unsigned int p = startAt;

    Address_SetTo(&b[p], ZT_ADDRESS_LENGTH, &id->_address);
    p += ZT_ADDRESS_LENGTH;

    if (b[p++] != 0) {
        printf("unsupported identity type\n");
        exit(0);
    }
    
    memcpy(id->_publicKey,b+p,(unsigned int)ZT_C25519_PUBLIC_KEY_LEN);
    p += ZT_C25519_PUBLIC_KEY_LEN;

    unsigned int privateKeyLength = (unsigned int)b[p++];
    if (privateKeyLength) {
        if (privateKeyLength != ZT_C25519_PRIVATE_KEY_LEN) {
            printf("invalid private key\n");
            exit(0);
        }
        memcpy(id->_privateKey,b+p,ZT_C25519_PRIVATE_KEY_LEN);
        p += ZT_C25519_PRIVATE_KEY_LEN;
    }

    return (p - startAt);
}

bool Identity_FromString(const char *str, Identity *id)
{
    char *f = NULL;
    if (!str)
        return false;

    char *saveptr = (char *)0;
    char tmp[1024];
    strncpy(tmp, str, sizeof(tmp));

    int fno = 0;
    for(f=strtok_r(tmp,":",&saveptr);(f);f=strtok_r((char *)0,":",&saveptr)) {
        switch(fno++) {
            case 0:
                id->_address = strtoull(f,(char **)0,16) & 0xffffffffffULL;
                if (Address_IsReserved(id->_address))
                    return false;
                break;
            case 1:
                if ((f[0] != '0')||(f[1]))
                    return false;
                break;
            case 2:
                if (Utils_unhex(f, strlen(f), id->_publicKey, sizeof(id->_publicKey)) != sizeof(id->_publicKey))
                    return false;
                break;
            case 3:
                if (Utils_unhex(f, strlen(f), id->_privateKey, sizeof(id->_privateKey)) != sizeof(id->_privateKey))
                    return false;
                break;
            default:
                return false;
        }
    }
    if (fno < 3)
        return false;

    return true;
}

char *Identity_ToString(const Identity *id,bool includePrivate)
{
    char *r=(char *)malloc(256);
    memset(r,0,256);

    char *p = Address_ToString(id->_address);
    char *idpub = Utils_hex(id->_publicKey,64);
    char * idpriv = Utils_hex(id->_privateKey,64);
    strcat(r, p);
    strcat(r,":0:"); // 0 == ZT_OBJECT_TYPE_IDENTITY
    strcat(r, idpub);

    unsigned char tmpKey[64]={0};
    bool havePrivateKey = memcmp(tmpKey,id->_privateKey,64)==0 ? false : true;
    if ((havePrivateKey)&&(includePrivate)) {
        strcat(r,":");
        strcat(r, idpriv);
    }
    free(p);
    free(idpub);
    free(idpriv);
    
    return r;
}


/***************************************************************
**Shortcut method to perform key agreement with another identity
***************************************************************/
bool Identity_Agree(const Identity *id,void *key,unsigned int klen) 
{
    if (RR->identity._privateKey) {
        C25519_agree(RR->identity._privateKey,id->_publicKey,key,klen);
        return true;
    }
    return false;
}


bool Identity_LocallyValidate(Identity *id)
{
    if (Address_IsReserved(id->_address))
        return false;

    unsigned char digest[64];
    char genmem[ZT_IDENTITY_GEN_MEMORY];
    _computeMemoryHardHash(id->_publicKey,64,digest,genmem);

    unsigned char addrb[5];
    Address_CopyTo(addrb, sizeof(addrb), id->_address);

    return (
        (digest[0] < ZT_IDENTITY_GEN_HASHCASH_FIRST_BYTE_LESS_THAN)&&
        (digest[59] == addrb[0])&&
        (digest[60] == addrb[1])&&
        (digest[61] == addrb[2])&&
        (digest[62] == addrb[3])&&
        (digest[63] == addrb[4]));
}

bool Identity_hasPrivate(Identity *id)
{
    return C25519_has_PrivateKey(id->_privateKey);
}

