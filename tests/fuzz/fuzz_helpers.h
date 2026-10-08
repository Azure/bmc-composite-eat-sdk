// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#ifndef COMPOSITE_EAT_FUZZ_HELPERS_H
#define COMPOSITE_EAT_FUZZ_HELPERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "composite_eat/generation_request.h"

static inline void fuzz_check(bool condition) {
    if (!condition) {
        abort();
    }
}

struct fuzz_input {
    const uint8_t *data;
    size_t size;
    size_t offset;
};

static inline uint8_t fuzz_byte(struct fuzz_input *input) {
    return input->offset < input->size ? input->data[input->offset++] : 0u;
}

static inline void fuzz_fill(struct fuzz_input *input, uint8_t *output, size_t length) {
    for (size_t index = 0u; index < length; ++index) {
        output[index] = fuzz_byte(input);
    }
}

static inline bool fuzz_is_zero(const void *data, size_t length) {
    const uint8_t *bytes = data;
    for (size_t index = 0u; index < length; ++index) {
        if (bytes[index] != 0u) {
            return false;
        }
    }
    return true;
}

static inline void fuzz_make_request(struct composite_eat_generation_request *request) {
    static const uint8_t environment[] = "env.device.0";
    memset(request, 0, sizeof(*request));
    request->version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    request->nonce_length = COMPOSITE_EAT_NONCE_LENGTH;
    request->record_count = 1u;
    memcpy(request->records[0].environment, environment, sizeof(environment) - 1u);
    request->records[0].environment_length = sizeof(environment) - 1u;
}

struct fuzz_output {
    uint8_t *data;
    size_t capacity;
    size_t length;
    size_t calls;
    size_t fail_after;
};

static inline int fuzz_write(void *context, const uint8_t *data, size_t length) {
    struct fuzz_output *output = context;
    fuzz_check(data != NULL && length != 0u);
    ++output->calls;
    if (output->length > output->fail_after || length > output->fail_after - output->length) {
        return -1;
    }
    fuzz_check(output->length <= output->capacity);
    fuzz_check(length <= output->capacity - output->length);
    memcpy(output->data + output->length, data, length);
    output->length += length;
    return 0;
}

#endif
