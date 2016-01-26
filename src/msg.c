/*
 * Copyright (c) 2016 The libpblc authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdint.h>
#include <msgpack.h>
#include <cmockery/pbc.h>

#include "msg.h"

#ifdef UNIT_TESTING
#include <cmockery/cmockery_override.h>
#endif

int
msg_header_marshal(msgpack_packer *pk, const msg_t *m) {
    REQUIRE(m != NULL);
    REQUIRE(pk != NULL);

    /* Header */
    msgpack_pack_uint32(pk, m->header.magic);
    msgpack_pack_uint32(pk, m->header.version);
    msgpack_pack_uint32(pk, m->header.type);

    return 0;
}

int
msg_header_unmarshal(msg_t *m,
        msgpack_unpacked *upk, 
        const char* data,
        size_t len,
        size_t* off) {

    REQUIRE(m != NULL);
    REQUIRE(upk != NULL);
    REQUIRE(data != NULL);
    REQUIRE(len > 0);

    msgpack_unpack_return ret;

    /* Magic */
    ret = msgpack_unpack_next(upk, data, len, off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }
    if (MSGPACK_OBJECT_POSITIVE_INTEGER != upk->data.type) {
        return -1;
    }
    m->header.magic = upk->data.via.u64;

    /* Version */
    ret = msgpack_unpack_next(upk, data, len, off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }
    if (MSGPACK_OBJECT_POSITIVE_INTEGER != upk->data.type) {
        return -1;
    }
    m->header.version = upk->data.via.u64;

    /* Type */
    ret = msgpack_unpack_next(upk, data, len, off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }
    if (MSGPACK_OBJECT_POSITIVE_INTEGER != upk->data.type) {
        return -1;
    }
    m->header.type = upk->data.via.u64;
    
    return 0;
}


msgpack_sbuffer *
msg_put_marshal(const msg_t *m) {
    REQUIRE(m != NULL);

    /* Create buffer for message */
	msgpack_sbuffer *sbuf = NULL;
	sbuf = msgpack_sbuffer_new();
    if (sbuf == NULL) {
        return sbuf;
    }

    /* Create packet */
    msgpack_packer pk;
    msgpack_packer_init(&pk, sbuf, msgpack_sbuffer_write);

    /* Header */
    msg_header_marshal(&pk, m);

    /* Msg */
    msgpack_pack_uint64(&pk, m->block);
    msgpack_pack_uint64(&pk, m->nblocks);

    int slen;
    slen = strnlen(m->path, MAX_PATH_SIZE);
    msgpack_pack_str(&pk, slen);
    msgpack_pack_str_body(&pk, m->path, slen);

    ENSURE(sbuf->size > 0);
    ENSURE(sbuf->data != NULL);

    return sbuf;
}

int
msg_unpack_next_u64(uint64_t *value,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off) {

    REQUIRE(value != NULL);
    REQUIRE(upk != NULL);
    REQUIRE(data != NULL);
    REQUIRE(len > 0);

    msgpack_unpack_return ret;

    ret = msgpack_unpack_next(upk, data, len, off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }
    if (MSGPACK_OBJECT_POSITIVE_INTEGER != upk->data.type) {
        return -1;
    }
    *value = upk->data.via.u64;

    ENSURE(*value == upk->data.via.u64);

    return 0;
}

int
msg_unpack_next_u32(uint32_t *value,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off) {

    uint64_t value64;
    int ret;

    ret = msg_unpack_next_u64(&value64, upk, data, len, off);
    if (0 > ret) {
        return ret;
    }
    *value = (uint32_t)value64;

    ENSURE(*value == (uint32_t)value64);

    return 0;
}

int
msg_put_unmarshal(msg_t *m,
        const char *data,
        size_t len) {
    REQUIRE(m != NULL);
    REQUIRE(data != NULL);
    REQUIRE(len > 0);

    int retval;
    size_t offset = 0;
    msgpack_unpack_return ret;
    msgpack_unpacked upk;

    if (0 > msg_header_unmarshal(m, &upk, data, len, &offset)) {
        return -1;
    }

    retval = msg_unpack_next_u64(&m->block, &upk, data, len, &offset);
    if (0 > retval) {
        return retval;
    }
    retval = msg_unpack_next_u64(&m->nblocks, &upk, data, len, &offset);
    if (0 > retval) {
        return retval;
    }

    ret = msgpack_unpack_next(&upk, data, len, &offset);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }
    if (MSGPACK_OBJECT_STR != upk.data.type) {
        return -1;
    }
    m->path = strndup(upk.data.via.str.ptr, upk.data.via.str.size);

    return 0;
}

msgpack_sbuffer *
msg_get_marshal(const msg_t *m) {
    return msg_put_marshal(m);
}
