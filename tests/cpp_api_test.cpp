// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cstddef>
#include <cstring>

#include "composite_eat/generation_request.h"
#include "composite_eat/token_builder.h"
#include "composite_eat/version.h"
#include "test_check.h"

static_assert(BMC_COMPOSITE_EAT_VERSION_MAJOR == 0);
static_assert(BMC_COMPOSITE_EAT_VERSION_MINOR == 8);
static_assert(BMC_COMPOSITE_EAT_VERSION_PATCH == 0);
static_assert(BMC_COMPOSITE_EAT_VERSION_PRERELEASE[0] == '\0');
static_assert(BMC_COMPOSITE_EAT_API_DRAFT == 1);

int main() {
    composite_eat_generation_request request{};
    std::size_t encodedLength = 0;
    int evaluations = 0;

    TEST_CHECK(++evaluations == 1);
    TEST_CHECK(evaluations == 1);

    request.version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    request.nonce_length = COMPOSITE_EAT_NONCE_LENGTH;
    std::memcpy(request.records[0].environment, "env.device.0", sizeof("env.device.0") - 1u);
    request.records[0].environment_length = sizeof("env.device.0") - 1u;
    request.record_count = 1u;
    return composite_eat_generation_request_encode(&request, nullptr, 0, &encodedLength) ==
                   COMPOSITE_EAT_BUFFER_TOO_SMALL
               ? 0
               : 1;
}
