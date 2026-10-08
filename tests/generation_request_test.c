// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "test_check.h"
#include <stdio.h>
#include <string.h>

#include "composite_eat/generation_request.h"

static void make_request(struct composite_eat_generation_request *request) {
    static const char environment[] = "env.device.0";
    size_t index;

    memset(request, 0, sizeof(*request));
    request->version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    request->nonce_length = 32u;
    for (index = 0; index < request->nonce_length; ++index) {
        request->nonce[index] = (uint8_t)index;
    }
    request->record_count = 1u;
    request->records[0].environment_length = sizeof(environment) - 1u;
    memcpy(request->records[0].environment, environment, sizeof(environment) - 1u);
    memset(request->records[0].digest, 0xa5, sizeof(request->records[0].digest));
}

static void round_trip(const struct composite_eat_generation_request *request) {
    static struct composite_eat_generation_request decoded;
    static uint8_t encoded[16384];
    static uint8_t encoded_again[16384];
    size_t encoded_length = 0u;
    size_t encoded_again_length = 0u;

    TEST_CHECK(composite_eat_generation_request_encode(request, encoded, sizeof(encoded),
                                                       &encoded_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_generation_request_encode(request, encoded_again,
                                                       sizeof(encoded_again),
                                                       &encoded_again_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(encoded_again_length == encoded_length);
    TEST_CHECK(memcmp(encoded, encoded_again, encoded_length) == 0);
    TEST_CHECK(composite_eat_generation_request_decode(encoded, encoded_length, &decoded) ==
               COMPOSITE_EAT_OK);
    TEST_CHECK(decoded.nonce_length == request->nonce_length);
    TEST_CHECK(decoded.record_count == request->record_count);
}

static void test_boundaries(void) {
    static struct composite_eat_generation_request request;
    size_t index;

    make_request(&request);
    request.record_count = COMPOSITE_EAT_MAX_DEVICE_RECORDS;
    for (index = 0; index < request.record_count; ++index) {
        int length =
            snprintf((char *)request.records[index].environment,
                     sizeof(request.records[index].environment), "env.device.%02zu", index);

        TEST_CHECK(length > 0);
        request.records[index].environment_length = (size_t)length;
        memset(request.records[index].digest, (int)index, sizeof(request.records[index].digest));
    }
    round_trip(&request);

    request.record_count = 1u;
    memcpy(request.records[0].environment, "env.", 4u);
    memset(&request.records[0].environment[4], 'a', COMPOSITE_EAT_MAX_ENVIRONMENT_LENGTH - 4u);
    request.records[0].environment_length = COMPOSITE_EAT_MAX_ENVIRONMENT_LENGTH;
    round_trip(&request);
}

static void test_profile_bounds(void) {
    static const size_t invalid_nonce_lengths[] = {0u, 8u, 31u, 33u, 64u};
    struct composite_eat_generation_request request;
    size_t index;

    make_request(&request);
    request.record_count = 0u;
    TEST_CHECK(composite_eat_validate_generation_request(&request) == COMPOSITE_EAT_BAD_ARGUMENT);

    for (index = 0u; index < sizeof(invalid_nonce_lengths) / sizeof(invalid_nonce_lengths[0]);
         ++index) {
        make_request(&request);
        request.nonce_length = invalid_nonce_lengths[index];
        TEST_CHECK(composite_eat_validate_generation_request(&request) ==
                   COMPOSITE_EAT_BAD_ARGUMENT);
    }
}

static void test_invalid_identifiers(void) {
    struct composite_eat_generation_request request;

    make_request(&request);
    memcpy(request.records[0].environment, "ENV.device.0", 12u);
    TEST_CHECK(composite_eat_validate_generation_request(&request) == COMPOSITE_EAT_BAD_ARGUMENT);

    make_request(&request);
    memcpy(request.records[0].environment, "env..device", 11u);
    request.records[0].environment_length = 11u;
    TEST_CHECK(composite_eat_validate_generation_request(&request) == COMPOSITE_EAT_BAD_ARGUMENT);

    make_request(&request);
    memcpy(request.records[0].environment, "device.0", 8u);
    request.records[0].environment_length = 8u;
    TEST_CHECK(composite_eat_validate_generation_request(&request) == COMPOSITE_EAT_BAD_ARGUMENT);
}

static void test_invalid_decode_arguments(void) {
    struct composite_eat_generation_request request;
    uint8_t encoded = 0u;

    memset(&request, 0xa5, sizeof(request));
    TEST_CHECK(composite_eat_generation_request_decode(NULL, 1u, &request) ==
               COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(request.version == 0u);
    TEST_CHECK(request.nonce_length == 0u);
    TEST_CHECK(request.record_count == 0u);

    memset(&request, 0xa5, sizeof(request));
    TEST_CHECK(composite_eat_generation_request_decode(&encoded, 0u, &request) ==
               COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(request.version == 0u);
    TEST_CHECK(request.nonce_length == 0u);
    TEST_CHECK(request.record_count == 0u);

    memset(&request, 0xa5, sizeof(request));
    TEST_CHECK(composite_eat_generation_request_decode(
                   &encoded, COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH + 1u, &request) ==
               COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(request.version == 0u);
    TEST_CHECK(request.nonce_length == 0u);
    TEST_CHECK(request.record_count == 0u);
}

static size_t build_nested_indefinite(uint8_t *encoded, bool indefinite_record,
                                      bool indefinite_digest) {
    uint8_t *cursor = encoded;

    *cursor++ = 0xa3;
    *cursor++ = 0x01;
    *cursor++ = 0x01;
    *cursor++ = 0x02;
    *cursor++ = 0x48;
    memset(cursor, 0x5a, 8u);
    cursor += 8u;
    *cursor++ = 0x03;
    *cursor++ = 0x81;
    *cursor++ = indefinite_record ? 0xbf : 0xa2;
    *cursor++ = 0x01;
    *cursor++ = 0x65;
    memcpy(cursor, "env.a", 5u);
    cursor += 5u;
    *cursor++ = 0x02;
    *cursor++ = indefinite_digest ? 0x9f : 0x82;
    *cursor++ = 0x38;
    *cursor++ = 0x2a;
    *cursor++ = 0x58;
    *cursor++ = 0x30;
    memset(cursor, 0xa5, COMPOSITE_EAT_SHA384_LENGTH);
    cursor += COMPOSITE_EAT_SHA384_LENGTH;
    if (indefinite_digest) {
        *cursor++ = 0xff;
    }
    if (indefinite_record) {
        *cursor++ = 0xff;
    }
    return (size_t)(cursor - encoded);
}

static size_t build_request_with_bounds(uint8_t *encoded, size_t nonce_length,
                                        bool include_record) {
    uint8_t *cursor = encoded;

    *cursor++ = 0xa3;
    *cursor++ = 0x01;
    *cursor++ = 0x01;
    *cursor++ = 0x02;
    if (nonce_length < 24u) {
        *cursor++ = (uint8_t)(0x40u | nonce_length);
    } else {
        *cursor++ = 0x58;
        *cursor++ = (uint8_t)nonce_length;
    }
    memset(cursor, 0x5a, nonce_length);
    cursor += nonce_length;
    *cursor++ = 0x03;
    if (!include_record) {
        *cursor++ = 0x80;
        return (size_t)(cursor - encoded);
    }

    *cursor++ = 0x81;
    *cursor++ = 0xa2;
    *cursor++ = 0x01;
    *cursor++ = 0x65;
    memcpy(cursor, "env.a", 5u);
    cursor += 5u;
    *cursor++ = 0x02;
    *cursor++ = 0x82;
    *cursor++ = 0x38;
    *cursor++ = 0x2a;
    *cursor++ = 0x58;
    *cursor++ = 0x30;
    memset(cursor, 0xa5, COMPOSITE_EAT_SHA384_LENGTH);
    cursor += COMPOSITE_EAT_SHA384_LENGTH;
    return (size_t)(cursor - encoded);
}

static void test_malformed_wire(void) {
    static const uint8_t tagged_request[] = {0xc0, 0xa3, 0x01, 0x01, 0x02, 0x48, 0,    1,
                                             2,    3,    4,    5,    6,    7,    0x03, 0x80};
    static const uint8_t indefinite_map[] = {0xbf, 0x01, 0x01, 0x02, 0x48, 0,    1,    2,
                                             3,    4,    5,    6,    7,    0x03, 0x80, 0xff};
    static const uint8_t indefinite_records[] = {0xa3, 0x01, 0x01, 0x02, 0x48, 0,    1,    2,
                                                 3,    4,    5,    6,    7,    0x03, 0x9f, 0xff};
    static const uint8_t tagged_nonce[] = {0xa3, 0x01, 0x01, 0x02, 0xc0, 0x48, 0,    1,
                                           2,    3,    4,    5,    6,    7,    0x03, 0x80};
    static const size_t invalid_nonce_lengths[] = {8u, 31u, 33u, 64u};
    uint8_t nested[192];
    size_t nested_length;
    size_t index;
    struct composite_eat_generation_request request;

    TEST_CHECK(
        composite_eat_generation_request_decode(tagged_request, sizeof(tagged_request), &request) ==
        COMPOSITE_EAT_MALFORMED_REQUEST);
    TEST_CHECK(
        composite_eat_generation_request_decode(indefinite_map, sizeof(indefinite_map), &request) ==
        COMPOSITE_EAT_MALFORMED_REQUEST);
    TEST_CHECK(composite_eat_generation_request_decode(indefinite_records,
                                                       sizeof(indefinite_records), &request) ==
               COMPOSITE_EAT_MALFORMED_REQUEST);
    TEST_CHECK(
        composite_eat_generation_request_decode(tagged_nonce, sizeof(tagged_nonce), &request) ==
        COMPOSITE_EAT_MALFORMED_REQUEST);

    nested_length = build_nested_indefinite(nested, true, false);
    TEST_CHECK(composite_eat_generation_request_decode(nested, nested_length, &request) ==
               COMPOSITE_EAT_MALFORMED_REQUEST);
    nested_length = build_nested_indefinite(nested, false, true);
    TEST_CHECK(composite_eat_generation_request_decode(nested, nested_length, &request) ==
               COMPOSITE_EAT_MALFORMED_REQUEST);

    nested_length = build_request_with_bounds(nested, COMPOSITE_EAT_NONCE_LENGTH, false);
    memset(&request, 0xa5, sizeof(request));
    TEST_CHECK(composite_eat_generation_request_decode(nested, nested_length, &request) ==
               COMPOSITE_EAT_MALFORMED_REQUEST);
    TEST_CHECK(request.version == 0u);
    TEST_CHECK(request.nonce_length == 0u);
    TEST_CHECK(request.record_count == 0u);

    for (index = 0u; index < sizeof(invalid_nonce_lengths) / sizeof(invalid_nonce_lengths[0]);
         ++index) {
        nested_length = build_request_with_bounds(nested, invalid_nonce_lengths[index], true);
        TEST_CHECK(composite_eat_generation_request_decode(nested, nested_length, &request) ==
                   COMPOSITE_EAT_MALFORMED_REQUEST);
    }
}

int main(void) {
    struct composite_eat_generation_request request;
    struct composite_eat_generation_request decoded;
    uint8_t encoded[512];
    size_t encoded_length = 0u;

    make_request(&request);
    request.version = 0u;
    encoded_length = 123u;
    TEST_CHECK(composite_eat_generation_request_encode(&request, encoded, sizeof(encoded),
                                                       &encoded_length) ==
               COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(encoded_length == 0u);

    make_request(&request);
    TEST_CHECK(composite_eat_generation_request_encode(&request, NULL, 0u, &encoded_length) ==
               COMPOSITE_EAT_BUFFER_TOO_SMALL);
    TEST_CHECK(encoded_length > 0u);
    TEST_CHECK(encoded_length < sizeof(encoded));
    encoded[0] = 0xa5u;
    TEST_CHECK(composite_eat_generation_request_encode(&request, encoded, 1u, &encoded_length) ==
               COMPOSITE_EAT_BUFFER_TOO_SMALL);
    TEST_CHECK(encoded[0] == 0xa5u);
    TEST_CHECK(encoded_length > 1u);
    TEST_CHECK(composite_eat_generation_request_encode(&request, encoded, sizeof(encoded),
                                                       &encoded_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_generation_request_decode(encoded, encoded_length, &decoded) ==
               COMPOSITE_EAT_OK);
    TEST_CHECK(decoded.version == request.version);
    TEST_CHECK(decoded.nonce_length == request.nonce_length);
    TEST_CHECK(memcmp(decoded.nonce, request.nonce, request.nonce_length) == 0);
    TEST_CHECK(decoded.record_count == 1u);
    TEST_CHECK(decoded.records[0].environment_length == request.records[0].environment_length);
    TEST_CHECK(memcmp(decoded.records[0].digest, request.records[0].digest,
                      sizeof(request.records[0].digest)) == 0);

    encoded[encoded_length] = 0u;
    TEST_CHECK(composite_eat_generation_request_decode(encoded, encoded_length + 1u, &decoded) ==
               COMPOSITE_EAT_MALFORMED_REQUEST);

    request.records[1] = request.records[0];
    request.record_count = 2u;
    TEST_CHECK(composite_eat_validate_generation_request(&request) == COMPOSITE_EAT_BAD_ARGUMENT);

    test_boundaries();
    test_profile_bounds();
    test_invalid_identifiers();
    test_invalid_decode_arguments();
    test_malformed_wire();

    return 0;
}
