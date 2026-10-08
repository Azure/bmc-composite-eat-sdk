// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <string.h>

#include "test_check.h"

#ifndef NDEBUG
#error This regression must be compiled with NDEBUG.
#endif

int main(int argc, char **argv) {
    int count = 0;

    if (argc == 2 && strcmp(argv[1], "--fail") == 0) {
        TEST_CHECK(0);
        return 0;
    }
    if (argc != 1) {
        return 2;
    }
    TEST_CHECK(++count == 1);
    TEST_CHECK(count == 1);
    return count == 1 ? 0 : 1;
}
