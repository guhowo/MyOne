#ifndef _JSON_CONTROLLER_H
#define _JSON_CONTROLLER_H

#include "./json/json.h"
#include "Utils.h"


static inline char *jsonString(const json_object *jv,const char *dfl)
{
    const char *s=json_object_get_string(jv);
    return (s==NULL) ? (char*)dfl : (char *)s;
}

static inline bool jsonBool(const json_object *jv,const bool dfl)
{
    return json_object_get_boolean(jv);
}

static inline uint64_t jsonInt(const json_object *jv,const uint64_t dfl)
{
    uint64_t val=json_object_get_int64(jv);    
    return (val==0) ? (uint64_t)dfl : val;
}


#endif

