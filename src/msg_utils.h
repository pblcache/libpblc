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

#ifndef LIBPBLC_MSG_UTILS_H_
#define LIBPBLC_MSG_UTILS_H_

int
msg_unpack_next_u32(uint32_t *value,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off);
int
msg_unpack_next_u64(uint64_t *value,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off);

int
msg_unpack_next_string(char **str,
        msgpack_unpacked *upk,
        const char *data,
        size_t len,
        size_t *off);

#endif /* MSG_UTILS_H_ */
