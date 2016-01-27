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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <inttypes.h>
#include <msgpack.h>

#include "msg.h"
#include <cmockery/cmockery.h>

static void
test_code_decode(void **state) {
    (void) state;

    msg_t orig_msg, decoded_msg;
    msgpack_sbuffer *sbuf;
    int ret;

    orig_msg.header.magic = 0xFF;
    orig_msg.header.version = 0xA5;
    orig_msg.header.type = PBLC_MSG_GET;
    orig_msg.block = 0xAABBCCDD;
    orig_msg.nblocks = 0xFFDDEE;
    orig_msg.path = "this/is/a/test";

    sbuf = msg_put_marshal(&orig_msg);
    assert_non_null(sbuf);
    assert_non_null(sbuf->data);
    assert_true(sbuf->size > 0);

    ret = msg_put_unmarshal(&decoded_msg,
            sbuf->data, sbuf->size);
    msgpack_sbuffer_free(sbuf);
    assert_int_equal(ret, 0);
    assert_int_equal(orig_msg.header.magic,
            decoded_msg.header.magic);

}

int main(void) {
    const UnitTest tests[] = {
        unit_test(test_code_decode),
    };

    return run_tests(tests, "msg_test");
}
