/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <cmocka.h>

#include "../../os_crypto/sha512/sha512_op.h"
#include "../../wrappers/common.h"
#include "../headers/shared.h"

void test_sha512_string() {
    const char *string = "teststring";
    const char *string_sha512 = "6253b39071e5df8b5098f59202d414c37a17d6a38a875ef5f8c7d89b0212b028692d3d2090ce03ae1de66c862fa8a561e57ed9eb7935ce627344f742c0931d72";
    os_sha512 buffer;

    OS_SHA512_String(string, buffer);

    assert_string_equal(buffer, string_sha512);
}

void test_sha512_hex() {
    unsigned char md[SHA512_DIGEST_LENGTH];
    const char *string = "teststring";
    os_sha512 buffer;
    SHA512_CTX c;

    // manual compute sha512
    SHA512_Init(&c);
    SHA512_Update(&c, string, strlen(string));
    SHA512_Final(&(md[0]), &c);

    const char *string_sha512 = "6253b39071e5df8b5098f59202d414c37a17d6a38a875ef5f8c7d89b0212b028692d3d2090ce03ae1de66c862fa8a561e57ed9eb7935ce627344f742c0931d72";

    OS_SHA512_Hex(md, buffer);

    // check hex output
    assert_string_equal(buffer, string_sha512);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sha512_string),
        cmocka_unit_test(test_sha512_hex)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
