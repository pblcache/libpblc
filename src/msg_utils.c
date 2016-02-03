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
#ifdef strndup
#undef strndup
#endif
#define strndup test_strndup
char * test_strndup(const char *s, size_t n);
#endif

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
        return -1;
    }
    *value = (uint32_t)value64;

    ENSURE(*value == (uint32_t)value64);

    return 0;
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
msg_unpack_next_string(char **str,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off) {

    REQUIRE(str != NULL);
    REQUIRE(upk != NULL);
    REQUIRE(data != NULL);
    REQUIRE(len > 0);

    msgpack_unpack_return ret;

    ret = msgpack_unpack_next(upk, data, len, off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        return -1;
    }
    if (MSGPACK_OBJECT_STR != upk->data.type) {
        return -1;
    }
    *str = strndup(upk->data.via.str.ptr, upk->data.via.str.size);
    if (*str == NULL) {
        return -1;
    }

    ENSURE(strlen(*str) == upk->data.via.str.size);
    ENSURE(strncmp(*str, upk->data.via.str.ptr, upk->data.via.str.size) == 0);

    return 0;
}
