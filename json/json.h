/*
 * $Id: json.h,v 1.6 2006/01/26 02:16:28 mclark Exp $
 *
 * Copyright (c) 2004, 2005 Metaparadigm Pte. Ltd.
 * Michael Clark <michael@metaparadigm.com>
 * Copyright (c) 2009 Hewlett-Packard Development Company, L.P.
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See COPYING for details.
 *
 */

#ifndef _json_h_
#define _json_h_

#ifdef __cplusplus
extern "C" {
#endif

#include "debug.h"
#include "linkhash.h"
#include "arraylist.h"
#include "json_util.h"
#include "json_object.h"
#include "json_pointer.h"
#include "json_tokener.h"
#include "json_object_iterator.h"
#include "json_c_version.h"

#define JSON_IS_NULL(obj) (json_object_get_type(obj) == json_type_null)
#define JSON_IS_OBJECT(obj) (json_object_get_type(obj) == json_type_object)
#define JSON_IS_ARRAY(obj) (json_object_get_type(obj) == json_type_array)
#define JSON_IS_STRING(obj) (json_object_get_type(obj) == json_type_string)
#define JSON_IS_INT(obj) (json_object_get_type(obj) == json_type_int)
#define JSON_IS_DOUBLE(obj) (json_object_get_type(obj) == json_type_double)
#define JSON_IS_NUMBER(obj) (json_object_get_type(obj) == json_type_int || json_object_get_type(obj) == json_type_double)
#define JSON_INT(obj, id) (json_object_get_int(json_object_object_get(obj,id)))


#ifdef __cplusplus
}
#endif

#endif
