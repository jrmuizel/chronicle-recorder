/*
    Copyright (c) 2006 Novell and contributors:
        robert@ocallahan.org
    
    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use,
    copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the
    Software is furnished to do so, subject to the following
    conditions:
    
    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
    OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
    OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef JSON_H__
#define JSON_H__

#include "util.h"

#include <stdint.h>
#include <stdio.h>

/*
 * These functions define an API for parsing and emitting JSON output.
 */

typedef enum {
  JSON_INVALID,
  JSON_OBJECT,
  JSON_ARRAY,
  JSON_STRING,
  JSON_INT,
  JSON_DOUBLE,
  JSON_NULL,
  JSON_TRUE,
  JSON_FALSE
} JSON_Type;

/**
 * A JSON node.
 */
typedef struct _JSON_Value JSON_Value;
struct _JSON_Value {
  JSON_Type type;
  union {
    const char* s; /* string: UTF8, null terminated */
    JSON_Value* a; /* array: JSON_INVALID terminated */
    int64_t     i; /* int */
    double      d; /* double */
    JSON_Value* o; /* object: JSON_INVALID terminated, alternating fields (strings) and values */
  } v;
};

/********** JSON input **********/

/**
 * Parse a JSON string to a value. The value is malloced and must be freed
 * by the caller. The caller has no other cleanup obligations.
 * Returns NULL on failure.
 */
JSON_Value* JSON_parse(const char* data, int len);

/**
 * Extract a field from an object.
 * @return NULL if no such field
 */
JSON_Value* JSON_get_field(JSON_Value* v, const char* name);

/**
 * Returns true if and only if v is a string with value s.
 */
int JSON_is_string(JSON_Value* v, const char* s);

/********** JSON output **********/

/**
 * An accumulator for building JSON data.
 */
typedef struct {
  CH_GrowBuf buf;
  int        buf_count;
  CH_GrowBuf block_buf;
  int        block_buf_count;
} JSON_Builder;

/**
 * Create a builder building an object.
 */
void JSON_builder_init_object(JSON_Builder* builder);
/**
 * Create a builder building an array.
 */
void JSON_builder_init_array(JSON_Builder* builder);
/**
 * XXX what was this for?
 */
void JSON_builder_init_copy_part(JSON_Builder* builder, JSON_Builder* source,
                                 int* index);
/**
 * Append an int to the builder. If field is non-NULL then the builder
 * must be building an object, otherwise it must be building an array.
 */
void JSON_append_int(JSON_Builder* builder, const char* field, int64_t i);
/**
 * Append a double to the builder. If field is non-NULL then the builder
 * must be building an object, otherwise it must be building an array.
 */
void JSON_append_double(JSON_Builder* builder, const char* field, double d);
/**
 * Append a string to the builder. If field is non-NULL then the builder
 * must be building an object, otherwise it must be building an array.
 * The string must stay around for at least the lifetime of the builder.
 */
void JSON_append_string(JSON_Builder* builder, const char* field, const char* str);
/**
 * Append a string to the builder. If field is non-NULL then the builder
 * must be building an object, otherwise it must be building an array.
 * This copies the string so it need not stay around longer than this call.
 */
void JSON_append_stringdup(JSON_Builder* builder, const char* field, const char* str);
/**
 * Append a string of hex-encoded bytes to the builder. If field is
 * non-NULL then the builder must be building an object, otherwise it
 * must be building an array. This copies the data so it need not stay around
 * longer than this call.
 */
void JSON_append_hex_string(JSON_Builder* builder, const char* field_name,
                            uint8_t* data, uintptr_t len);
/**
 * Append a string of hex-encoded bytes to the builder. If field is
 * non-NULL then the builder must be building an object, otherwise it
 * must be building an array. This copies the data so it need not stay around
 * longer than this call. The bytes are output in reverse order.
 */
void JSON_append_hex_string_byteswapped(JSON_Builder* builder, const char* field_name,
                                        uint8_t* data, uintptr_t len);
/**
 * Append a printf-formatted string to the builder. If field is
 * non-NULL then the builder must be building an object, otherwise it
 * must be building an array.
 */
void JSON_append_stringf(JSON_Builder* builder, const char* field,
                         const char* format, ...);
/**
 * Append a boolean ('true' or 'false' literal) to the builder. If field is
 * non-NULL then the builder must be building an object, otherwise it
 * must be building an array.
 */
void JSON_append_boolean(JSON_Builder* builder, const char* field, int b);
/**
 * Append a primitive literal to the builder (e.g. 'null', 'true' or
 * 'false'). If field is non-NULL then the builder must be building an object,
 * otherwise it must be building an array.
 */
void JSON_append_simple(JSON_Builder* builder, const char* field, JSON_Type t);
/**
 * Append an object to the builder. If field is non-NULL then the builder
 * must be building an object, otherwise it must be building an array.
 * Further updates to the builder update the new object, until JSON_close_object
 * is called on the builder.
 */
void JSON_open_object(JSON_Builder* builder, const char* field);
/**
 * Stop appending to a nested object and return to the outer object or array.
 */
void JSON_close_object(JSON_Builder* builder);
/**
 * Append an array to the builder. If field is non-NULL then the builder
 * must be building an object, otherwise it must be building an array.
 * Further updates to the builder update the new array, until JSON_close_array
 * is called on the builder.
 */
void JSON_open_array(JSON_Builder* builder, const char* field);
/**
 * Stop appending to a nested array and return to the outer object or array.
 */
void JSON_close_array(JSON_Builder* builder);

/**
 * Write the JSON data to 'output', then clean up and destroy the builder.
 * Any open objects or arrays are automatically closed first.
 */
void JSON_builder_done_write(JSON_Builder* builder, FILE* output);
/**
 * Clean up and destroy the builder. Nothing is output --- the data is just
 * lost.
 */
void JSON_builder_done(JSON_Builder* builder);
/**
 * Create a fresh JSON_Value for the builder's data, then clean up and
 * destroy the builder. Any open objects or arrays are automatically closed
 * first. Returns NULL on failure. Otherwise the return value is malloced
 * and the caller is responsible for freeing it.
 */
JSON_Value* JSON_builder_done_value(JSON_Builder* builder);

/**
 * Write a JSON_Value to 'output'.
 */
void JSON_write(FILE* output, JSON_Value* v);

#endif
