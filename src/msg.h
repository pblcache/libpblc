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

#ifndef LIBPBLC_MSG_H_
#define LIBPBLC_MSG_H_

#include <stdint.h>

#define MAX_PATH_SIZE 2048

typedef enum {
    PBLC_MSG_NOOP = 0,
    PBLC_MSG_PUT = 1,
    PBLC_MSG_GET = 2
} msg_type_t;

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t type;
} msg_header_t;

typedef struct {
    msg_header_t header;
    uint64_t block;
    uint64_t nblocks;
    char *path;
} msg_t;
    
int
msg_header_marshal(msgpack_packer *pk, const msg_t *m);
int
msg_header_unmarshal(msg_t *m,
        msgpack_unpacked *upk, 
        const char* data,
        size_t len,
        size_t* off);
msgpack_sbuffer *
msg_put_marshal(const msg_t *m);
int
msg_unpack_next_u64(uint64_t *value,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off);
int
msg_unpack_next_u32(uint32_t *value,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off);
int
msg_put_unmarshal(msg_t *m,
        const char *data,
        size_t len);
msgpack_sbuffer *msg_get_marshal(const msg_t *m);
void msg_destroy(msg_t *m);

#endif /* LIBPBLC_MSG_H_ */
