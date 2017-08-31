#include "Dictionary.h"

void Dictionary_Init(Dictionary *metaData,const char *s)
{
	unsigned int len=metaData->len;
	unsigned char *data=metaData->b;
	if (s) {
		if (len > (ZT_NETWORKCONFIG_METADATA_DICT_CAPACITY-1))
			len = ZT_NETWORKCONFIG_METADATA_DICT_CAPACITY-1;
		memcpy(data,s,len);
			data[len] = (char)0;
	} else {
		data[0] = (char)0;
	}	
}

int Dictionary_Get(const Dictionary *metaData,const char *key,char *dest,unsigned int destlen)
{
	const char *p = metaData->b;
	const char *const eof = p + ZT_NETWORKCONFIG_METADATA_DICT_CAPACITY;
	const char *k;
	bool esc;
	int j;

	if (!destlen) // sanity check
		return -1;

	while (*p) {
		k = key;
		while ((*k)&&(*p)) {
			if (*p != *k)
				break;
			++k;
			if (++p == eof) {
				dest[0] = (char)0;
				return -1;
			}
		}

		if ((!*k)&&(*p == '=')) {
			j = 0;
			esc = false;
			++p;
			while ((*p != 0)&&(*p != 13)&&(*p != 10)) {
				if (esc) {
					esc = false;
					switch(*p) {
						case 'r': dest[j++] = 13; break;
						case 'n': dest[j++] = 10; break;
						case '0': dest[j++] = (char)0; break;
						case 'e': dest[j++] = '='; break;
						default: dest[j++] = *p; break;
					}
					if (j == (int)destlen) {
						dest[j-1] = (char)0;
						return j-1;
					}
				} else if (*p == '\\') {
					esc = true;
				} else {
					dest[j++] = *p;
					if (j == (int)destlen) {
						dest[j-1] = (char)0;
						return j-1;
					}
				}
				if (++p == eof) {
					dest[0] = (char)0;
					return -1;
				}
			}
			dest[j] = (char)0;
			return j;
		} else {
			while ((*p)&&(*p != 13)&&(*p != 10)) {
				if (++p == eof) {
					dest[0] = (char)0;
					return -1;
				}
			}
			if (*p) {
				if (++p == eof) {
					dest[0] = (char)0;
					return -1;
				}
			}
			else break;
		}
	}

	dest[0] = (char)0;
	return -1;
}


uint64_t Dictionary_GetUI(const Dictionary *metaData,const char *key,uint64_t dfl)
{
	char tmp[128];
	if (Dictionary_Get(metaData,key,tmp,sizeof(tmp)) >= 1)
		return Utils_hexStrToU64(tmp);
	return dfl;
}

bool Dictionary_GetToBuffer(const Dictionary *metaData,const char *key,Buffer *dest)
{
	const int r = Dictionary_Get(metaData,key,dest->b,1024*5);		//1024*5 is the maximum size of Buffer
	if (r >= 0) {
		dest->len = (unsigned int)r;
		return true;
	} else {
		dest->len = 0;
		return false;
	}
}

