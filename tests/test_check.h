// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef COMPOSITE_EAT_TEST_CHECK_H
#define COMPOSITE_EAT_TEST_CHECK_H

#include <stdio.h>
#include <stdlib.h>

static inline void test_check_result(int condition, const char *expression, const char *file,
                                     int line) {
    if (!condition) {
        fprintf(stderr, "%s:%d: check failed: %s\n", file, line, expression);
        exit(EXIT_FAILURE);
    }
}

#define TEST_CHECK(expression) test_check_result(!!(expression), #expression, __FILE__, __LINE__)

#endif
