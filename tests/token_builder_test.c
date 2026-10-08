// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "test_check.h"
#include <string.h>

#include "composite_eat/token_builder.h"

struct test_output {
    uint8_t *data;
    size_t capacity;
    size_t length;
};

static int write_output(void *context, const uint8_t *data, size_t length) {
    struct test_output *output = context;

    if ((output == NULL) || ((data == NULL) && (length != 0u)) ||
        (output->length > output->capacity) || ((output->capacity - output->length) < length)) {
        return -1;
    }
    memcpy(&output->data[output->length], data, length);
    output->length += length;
    return 0;
}

static int discard_output(void *context, const uint8_t *data, size_t length) {
    (void)context;
    return ((data != NULL) || (length == 0u)) ? 0 : -1;
}

static int fail_output(void *context, const uint8_t *data, size_t length) {
    (void)context;
    (void)data;
    (void)length;
    return -1;
}

enum evidence_write_mode {
    EVIDENCE_WRITE_EXACT,
    EVIDENCE_WRITE_SHORT,
    EVIDENCE_WRITE_LONG,
    EVIDENCE_WRITE_FAIL,
};

struct evidence_source {
    const uint8_t *data;
    size_t length;
    enum evidence_write_mode mode;
};

static int write_evidence(void *context, composite_eat_write write, void *write_context) {
    const struct evidence_source *source = context;
    static const uint8_t extra = 0u;
    size_t length = source->length;

    if (source->mode == EVIDENCE_WRITE_FAIL) {
        return -1;
    }
    if (source->mode == EVIDENCE_WRITE_SHORT) {
        --length;
    }
    if (write(write_context, source->data, length) != 0) {
        return -1;
    }
    if ((source->mode == EVIDENCE_WRITE_LONG) &&
        (write(write_context, &extra, sizeof(extra)) != 0)) {
        return -1;
    }
    return 0;
}

static void make_request(struct composite_eat_generation_request *request) {
    static const char environment[] = "env.device.0";

    memset(request, 0, sizeof(*request));
    request->version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    request->nonce_length = 32u;
    memset(request->nonce, 0x11, request->nonce_length);
    request->record_count = 1u;
    request->records[0].environment_length = sizeof(environment) - 1u;
    memcpy(request->records[0].environment, environment, sizeof(environment) - 1u);
    memset(request->records[0].digest, 0x22, sizeof(request->records[0].digest));
}

static void build_with_signature(const struct composite_eat_generation_request *request,
                                 const struct composite_eat_evidence_snapshot *evidence,
                                 const struct composite_eat_attestation_identity *identity,
                                 const uint8_t thumbprint[COMPOSITE_EAT_SHA384_LENGTH],
                                 const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH],
                                 uint8_t *response, size_t response_capacity,
                                 size_t *response_length) {
    struct composite_eat_workspace workspace;
    struct composite_eat_prepared prepared;

    TEST_CHECK(composite_eat_prepare(request, evidence, identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_write_signing_input(&prepared, discard_output, NULL) ==
               COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_finish(&prepared, signature, response, response_capacity,
                                    response_length) == COMPOSITE_EAT_OK);
}

int main(void) {
    static const uint8_t ueid[] = {0x01, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                   0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};
    static const uint8_t profile[] = "https://example.org/composite-eat/profile/v1";
    static const uint8_t local_evidence_bytes[] = {0xa1, 0x01, 0x43, 0xaa, 0xbb, 0xcc};
    static const uint8_t leaf_certificate[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    struct composite_eat_generation_request request;
    struct composite_eat_local_evidence local_evidence = {0};
    struct composite_eat_evidence_snapshot evidence;
    struct composite_eat_der_certificate certificate;
    struct composite_eat_attestation_identity identity;
    struct composite_eat_workspace workspace;
    struct composite_eat_prepared prepared;
    uint8_t thumbprint[COMPOSITE_EAT_SHA384_LENGTH];
    uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH];
    uint8_t signing_input[COMPOSITE_EAT_PAYLOAD_MAX + COMPOSITE_EAT_PROTECTED_MAX + 32u];
    uint8_t response[COMPOSITE_EAT_PAYLOAD_MAX + 512u];
    uint8_t response_again[COMPOSITE_EAT_PAYLOAD_MAX + 512u];
    uint8_t streamed_response[COMPOSITE_EAT_PAYLOAD_MAX + 512u];
    struct test_output signing_output = {signing_input, sizeof(signing_input), 0u};
    struct test_output response_output = {streamed_response, sizeof(streamed_response), 0u};
    struct evidence_source evidence_source = {local_evidence_bytes, sizeof(local_evidence_bytes),
                                              EVIDENCE_WRITE_EXACT};
    size_t signing_length = 0u;
    size_t response_length = 0u;
    size_t response_again_length = 0u;
    enum composite_eat_status status;

    make_request(&request);
    local_evidence.content_format = 60u;
    local_evidence.encoded =
        (struct composite_eat_buffer){local_evidence_bytes, sizeof(local_evidence_bytes)};
    evidence.ueid = (struct composite_eat_buffer){ueid, sizeof(ueid)};
    evidence.profile = (struct composite_eat_buffer){profile, sizeof(profile) - 1u};
    evidence.local_evidence = &local_evidence;
    evidence.local_evidence_count = 1u;
    certificate =
        (struct composite_eat_der_certificate){leaf_certificate, sizeof(leaf_certificate)};
    identity.certificates = &certificate;
    identity.certificate_count = 1u;
    memset(thumbprint, 0x33, sizeof(thumbprint));
    memset(signature, 0x44, sizeof(signature));

    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    response_length = 123u;
    TEST_CHECK(composite_eat_finish(&prepared, signature, response, sizeof(response),
                                    &response_length) == COMPOSITE_EAT_STATE_ERROR);
    TEST_CHECK(response_length == 0u);

    status = composite_eat_write_signing_input(&prepared, write_output, &signing_output);
    TEST_CHECK(status == COMPOSITE_EAT_OK);
    signing_length = signing_output.length;
    TEST_CHECK(signing_length > prepared.payload_length);
    TEST_CHECK(signing_input[0] == 0x84u);

    TEST_CHECK(composite_eat_finish(&prepared, signature, NULL, 0u, &response_length) ==
               COMPOSITE_EAT_BUFFER_TOO_SMALL);
    TEST_CHECK(response_length > 3u);
    TEST_CHECK(response_length < sizeof(response));
    response[0] = 0xa5u;
    TEST_CHECK(composite_eat_finish(&prepared, signature, response, 1u, &response_length) ==
               COMPOSITE_EAT_BUFFER_TOO_SMALL);
    TEST_CHECK(response[0] == 0xa5u);
    TEST_CHECK(response_length > 1u);
    response_output.length = 0u;
    TEST_CHECK(composite_eat_finish_write(&prepared, signature, write_output, &response_output, 1u,
                                          &response_again_length) ==
               COMPOSITE_EAT_BUFFER_TOO_SMALL);
    TEST_CHECK(response_output.length == 0u);
    TEST_CHECK(response_again_length == response_length);
    response_again_length = 123u;
    TEST_CHECK(composite_eat_finish_write(&prepared, signature, fail_output, NULL, sizeof(response),
                                          &response_again_length) == COMPOSITE_EAT_WRITE_ERROR);
    TEST_CHECK(response_again_length == 0u);
    TEST_CHECK(composite_eat_finish(&prepared, signature, response, sizeof(response),
                                    &response_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_finish_write(&prepared, signature, write_output, &response_output,
                                          sizeof(streamed_response),
                                          &response_again_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(response_output.length == response_length);
    TEST_CHECK(response_again_length == response_length);
    TEST_CHECK(memcmp(streamed_response, response, response_length) == 0);
    TEST_CHECK(response[0] == 0xd8u);
    TEST_CHECK(response[1] == 0x3du);
    TEST_CHECK(response[2] == 0xd2u);
    TEST_CHECK(composite_eat_finish(&prepared, signature, response_again, sizeof(response_again),
                                    &response_again_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(response_again_length == response_length);
    TEST_CHECK(memcmp(response_again, response, response_length) == 0);

    local_evidence.encoded = (struct composite_eat_buffer){0};
    local_evidence.encoded_length = evidence_source.length;
    local_evidence.write = write_evidence;
    local_evidence.write_context = &evidence_source;
    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_write_signing_input(&prepared, discard_output, NULL) ==
               COMPOSITE_EAT_OK);
    response_again_length = 0u;
    TEST_CHECK(composite_eat_finish(&prepared, signature, response_again, sizeof(response_again),
                                    &response_again_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(response_again_length == response_length);
    TEST_CHECK(memcmp(response_again, response, response_length) == 0);

    evidence_source.mode = EVIDENCE_WRITE_SHORT;
    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_write_signing_input(&prepared, discard_output, NULL) ==
               COMPOSITE_EAT_WRITE_ERROR);
    evidence_source.mode = EVIDENCE_WRITE_LONG;
    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_write_signing_input(&prepared, discard_output, NULL) ==
               COMPOSITE_EAT_WRITE_ERROR);
    evidence_source.mode = EVIDENCE_WRITE_FAIL;
    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_write_signing_input(&prepared, discard_output, NULL) ==
               COMPOSITE_EAT_WRITE_ERROR);

    local_evidence.encoded =
        (struct composite_eat_buffer){local_evidence_bytes, sizeof(local_evidence_bytes)};
    local_evidence.encoded_length = 0u;
    local_evidence.write = NULL;
    local_evidence.write_context = NULL;

    local_evidence.encoded_length = sizeof(local_evidence_bytes);
    local_evidence.write = write_evidence;
    local_evidence.write_context = &evidence_source;
    TEST_CHECK(composite_eat_validate_evidence_snapshot(&evidence) == COMPOSITE_EAT_BAD_ARGUMENT);
    local_evidence.encoded = (struct composite_eat_buffer){0};
    local_evidence.encoded_length = 0u;
    local_evidence.write = NULL;
    local_evidence.write_context = NULL;
    TEST_CHECK(composite_eat_validate_evidence_snapshot(&evidence) == COMPOSITE_EAT_BAD_ARGUMENT);
    local_evidence.encoded =
        (struct composite_eat_buffer){local_evidence_bytes, sizeof(local_evidence_bytes)};

    certificate.length = COMPOSITE_EAT_MAX_CERTIFICATE_LENGTH + 1u;
    response_again_length = 123u;
    TEST_CHECK(composite_eat_finish(&prepared, signature, response_again, sizeof(response_again),
                                    &response_again_length) == COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(response_again_length == 0u);
    certificate.length = sizeof(leaf_certificate);

    composite_eat_clear(&workspace, &prepared);
    TEST_CHECK(!prepared.ready);
    {
        const uint8_t *workspace_bytes = (const uint8_t *)&workspace;
        const uint8_t *prepared_bytes = (const uint8_t *)&prepared;
        size_t index;

        for (index = 0u; index < sizeof(workspace); ++index) {
            TEST_CHECK(workspace_bytes[index] == 0u);
        }
        for (index = 0u; index < sizeof(prepared); ++index) {
            TEST_CHECK(prepared_bytes[index] == 0u);
        }
    }
    TEST_CHECK(composite_eat_write_signing_input(&prepared, discard_output, NULL) ==
               COMPOSITE_EAT_STATE_ERROR);

    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    local_evidence.encoded.length = COMPOSITE_EAT_MAX_LOCAL_EVIDENCE_LENGTH + 1u;
    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(!prepared.ready);
    local_evidence.encoded.length = sizeof(local_evidence_bytes);

    certificate.length = COMPOSITE_EAT_MAX_CERTIFICATE_LENGTH + 1u;
    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_BAD_ARGUMENT);

    certificate.length = sizeof(leaf_certificate);
    {
        static const uint8_t maximum_evidence[COMPOSITE_EAT_MAX_LOCAL_EVIDENCE_LENGTH] = {0};
        struct composite_eat_local_evidence entries[COMPOSITE_EAT_MAX_LOCAL_EVIDENCE];
        struct composite_eat_evidence_snapshot aggregate = evidence;
        size_t index;

        memset(entries, 0, sizeof(entries));
        for (index = 0u; index < COMPOSITE_EAT_MAX_LOCAL_EVIDENCE; ++index) {
            entries[index].content_format = (uint16_t)(60u + index);
            entries[index].encoded =
                (struct composite_eat_buffer){maximum_evidence, sizeof(maximum_evidence)};
        }
        aggregate.local_evidence = entries;
        aggregate.local_evidence_count = COMPOSITE_EAT_MAX_LOCAL_EVIDENCE;
        TEST_CHECK(composite_eat_validate_evidence_snapshot(&aggregate) == COMPOSITE_EAT_OK);
        TEST_CHECK(composite_eat_prepare(&request, &aggregate, &identity, thumbprint, &workspace,
                                         &prepared) == COMPOSITE_EAT_ENCODING_ERROR);
        TEST_CHECK(!prepared.ready);
    }

    {
        struct composite_eat_generation_request reversed;
        struct composite_eat_device_record temporary;
        uint8_t ordered_token[COMPOSITE_EAT_PAYLOAD_MAX + 512u];
        uint8_t reversed_token[COMPOSITE_EAT_PAYLOAD_MAX + 512u];
        size_t ordered_length;
        size_t reversed_length;

        make_request(&request);
        memcpy(request.records[0].environment, "env.device.1", 12u);
        request.records[1] = request.records[0];
        memcpy(request.records[1].environment, "env.device.0", 12u);
        memset(request.records[1].digest, 0x77, sizeof(request.records[1].digest));
        request.record_count = 2u;
        reversed = request;
        temporary = reversed.records[0];
        reversed.records[0] = reversed.records[1];
        reversed.records[1] = temporary;

        build_with_signature(&request, &evidence, &identity, thumbprint, signature, ordered_token,
                             sizeof(ordered_token), &ordered_length);
        build_with_signature(&reversed, &evidence, &identity, thumbprint, signature, reversed_token,
                             sizeof(reversed_token), &reversed_length);
        TEST_CHECK(ordered_length == reversed_length);
        TEST_CHECK(memcmp(ordered_token, reversed_token, ordered_length) == 0);
    }

    make_request(&request);
    TEST_CHECK(composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                     &prepared) == COMPOSITE_EAT_OK);
    TEST_CHECK(composite_eat_write_signing_input(&prepared, fail_output, NULL) ==
               COMPOSITE_EAT_WRITE_ERROR);
    TEST_CHECK(!prepared.signing_complete);

    return 0;
}
