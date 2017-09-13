#ifndef _ZT_DICTIONARY_H
#define _ZT_DICTIONARY_H

#include "Constants.h"
#include "Utils.h"
#include "Buffer.h"

#include <stdint.h>

// Dictionary capacity needed for max size network meta-data
#define ZT_NETWORKCONFIG_METADATA_DICT_CAPACITY 1024

typedef struct _Dictionary{
	char b[ZT_NETWORKCONFIG_METADATA_DICT_CAPACITY];
	unsigned int len;
}Dictionary;


//Initialize metaData
void Dictionary_Init(Dictionary *metaData,const char *s);
//Get an entry
int Dictionary_Get(const Dictionary *metaData,const char *key,char *dest,unsigned int destlen);
//Get an unsigned int64 stored as hex in the dictionary
uint64_t Dictionary_GetUI(const Dictionary *metaData,const char *key,uint64_t dfl);
bool Dictionary_GetToBuffer(const Dictionary *metaData,const char *key,Buffer *dest);
bool Dictionary_add(Dictionary *d,const char *key,const char *value,int vlen);
bool Dictionary_addUint64(Dictionary *d,const char *key,uint64_t value);
bool Dictionary_addBuffer(Dictionary *d,const char *key,const Buffer *value);


#endif
