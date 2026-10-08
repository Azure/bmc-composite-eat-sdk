// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include <string.h>

#include "composite_eat/generation_request.h"
#include "fuzz_helpers.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct composite_eat_generation_request request;
    struct composite_eat_generation_request decoded;
    uint8_t encoded[COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH + 1u];
    uint8_t encoded_again[COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH];
    size_t encoded_length = 0u;
    size_t encoded_again_length = 0u;
    enum composite_eat_status status;

    memset(&request, 0xa5, sizeof(request));
    status = composite_eat_generation_request_decode(data, size, &request);
    if (status != COMPOSITE_EAT_OK) {
        fuzz_check(fuzz_is_zero(&request, sizeof(request)));
        return 0;
    }

    fuzz_check(composite_eat_validate_generation_request(&request) == COMPOSITE_EAT_OK);
    fuzz_check(composite_eat_generation_request_encode(&request, NULL, 0u, &encoded_length) ==
               COMPOSITE_EAT_BUFFER_TOO_SMALL);
    fuzz_check(encoded_length <= COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH);
    fuzz_check(composite_eat_generation_request_encode(&request, encoded, sizeof(encoded),
                                                       &encoded_length) == COMPOSITE_EAT_OK);
    fuzz_check(composite_eat_generation_request_decode(encoded, encoded_length, &decoded) ==
               COMPOSITE_EAT_OK);
    fuzz_check(composite_eat_generation_request_encode(&decoded, encoded_again,
                                                       sizeof(encoded_again),
                                                       &encoded_again_length) == COMPOSITE_EAT_OK);
    fuzz_check(encoded_length == encoded_again_length);
    fuzz_check(memcmp(encoded, encoded_again, encoded_length) == 0);

    encoded[encoded_length] = 0u;
    fuzz_check(composite_eat_generation_request_decode(encoded, encoded_length + 1u, &decoded) !=
               COMPOSITE_EAT_OK);
    fuzz_check(fuzz_is_zero(&decoded, sizeof(decoded)));
    fuzz_check(composite_eat_generation_request_decode(encoded, encoded_length - 1u, &decoded) !=
               COMPOSITE_EAT_OK);
    fuzz_check(fuzz_is_zero(&decoded, sizeof(decoded)));
    return 0;
}
