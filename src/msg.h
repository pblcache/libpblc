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
    

#endif /* LIBPBLC_MSG_H_ */
