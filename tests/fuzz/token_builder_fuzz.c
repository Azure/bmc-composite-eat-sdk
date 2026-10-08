// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "composite_eat/token_builder.h"
#include "fuzz_helpers.h"

struct fuzz_evidence {
    const uint8_t *data;
    size_t length;
    unsigned mode;
};

static int write_evidence(void *context, composite_eat_write write, void *write_context) {
    const struct fuzz_evidence *evidence = context;
    static const uint8_t extra = 0u;
    if (evidence->mode == 3u) {
        return -1;
    }
    size_t length = evidence->length - (evidence->mode == 1u ? 1u : 0u);
    if (write(write_context, evidence->data, length) != 0) {
        return -1;
    }
    return evidence->mode == 2u ? write(write_context, &extra, 1u) : 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t profile[] = "https://example.org/fuzz-profile";
    static const uint8_t ueid[] = {1u, 1u, 1u, 1u, 1u, 1u, 1u};
    static const uint8_t certificate_bytes[] = {0x30u, 0x03u, 0x02u, 0x01u, 0x01u};
    struct fuzz_input input = {data, size, 0u};
    uint8_t flags = fuzz_byte(&input);
    uint8_t evidence_bytes[256];
    uint8_t thumbprint[COMPOSITE_EAT_SHA384_LENGTH];
    uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH];
    uint8_t response[COMPOSITE_EAT_MAX_RESPONSE_LENGTH];
    uint8_t response_again[COMPOSITE_EAT_MAX_RESPONSE_LENGTH];
    struct composite_eat_generation_request request;
    struct composite_eat_generation_request invalid_request;
    struct composite_eat_workspace workspace = {0};
    struct composite_eat_prepared prepared = {0};
    struct fuzz_evidence source = {evidence_bytes, 1u + fuzz_byte(&input), (flags >> 4u) & 3u};
    struct composite_eat_local_evidence local = {.content_format = 60u};
    struct composite_eat_evidence_snapshot evidence = {
        .ueid = {ueid, sizeof(ueid)},
        .profile = {profile, sizeof(profile) - 1u},
        .local_evidence = &local,
        .local_evidence_count = 1u,
    };
    struct composite_eat_der_certificate certificate = {certificate_bytes,
                                                        sizeof(certificate_bytes)};
    struct composite_eat_attestation_identity identity = {&certificate, 1u};
    bool ready = false;
    bool signed_input = false;
    bool stream_error = (flags & 8u) != 0u && source.mode != 0u;
    bool valid = (flags & 7u) == 0u;

    fuzz_make_request(&request);
    fuzz_fill(&input, request.nonce, sizeof(request.nonce));
    fuzz_fill(&input, thumbprint, sizeof(thumbprint));
    fuzz_fill(&input, signature, sizeof(signature));
    fuzz_fill(&input, evidence_bytes, sizeof(evidence_bytes));
    if ((flags & 1u) != 0u) {
        request.nonce_length = 0u;
    }
    if ((flags & 2u) != 0u) {
        evidence.ueid.length = 0u;
    }
    if ((flags & 4u) != 0u) {
        identity.certificate_count = 0u;
    }
    if ((flags & 8u) != 0u) {
        local.encoded_length = source.length;
        local.write = write_evidence;
        local.write_context = &source;
    } else {
        local.encoded = (struct composite_eat_buffer){source.data, source.length};
    }
    invalid_request = request;
    invalid_request.nonce_length = 0u;
    input.offset = size > 0u ? 1u : 0u;

    for (size_t step = 0u; step < 32u; ++step) {
        unsigned operation = fuzz_byte(&input) % 9u;
        struct fuzz_output output = {response, sizeof(response), 0u, 0u, SIZE_MAX};
        size_t response_length = 123u;
        size_t second_length = 0u;
        enum composite_eat_status status;
        enum composite_eat_status finish_status = !ready         ? COMPOSITE_EAT_BAD_ARGUMENT
                                                  : signed_input ? COMPOSITE_EAT_OK
                                                                 : COMPOSITE_EAT_STATE_ERROR;
        switch (operation) {
        case 0u:
            status = composite_eat_prepare(&request, &evidence, &identity, thumbprint, &workspace,
                                           &prepared);
            fuzz_check(status == (valid ? COMPOSITE_EAT_OK : COMPOSITE_EAT_BAD_ARGUMENT));
            ready = valid;
            signed_input = false;
            break;
        case 1u:
            status = composite_eat_write_signing_input(&prepared, fuzz_write, &output);
            fuzz_check(status == (!ready         ? COMPOSITE_EAT_STATE_ERROR
                                  : stream_error ? COMPOSITE_EAT_WRITE_ERROR
                                                 : COMPOSITE_EAT_OK));
            signed_input = ready && !stream_error;
            break;
        case 2u:
            status = composite_eat_finish(&prepared, signature, response, sizeof(response),
                                          &response_length);
            fuzz_check(status == finish_status);
            if (status == COMPOSITE_EAT_OK) {
                fuzz_check(response_length > 0u && response_length <= sizeof(response));
                fuzz_check(composite_eat_finish(&prepared, signature, response_again,
                                                sizeof(response_again),
                                                &second_length) == COMPOSITE_EAT_OK);
                fuzz_check(response_length == second_length);
                fuzz_check(memcmp(response, response_again, response_length) == 0);
                output.data = response_again;
                fuzz_check(composite_eat_finish_write(&prepared, signature, fuzz_write, &output,
                                                      sizeof(response_again),
                                                      &second_length) == COMPOSITE_EAT_OK);
                fuzz_check(output.length == response_length && second_length == response_length);
                fuzz_check(memcmp(response, response_again, response_length) == 0);
            } else {
                fuzz_check(response_length == 0u);
            }
            break;
        case 3u:
            status = composite_eat_finish_write(&prepared, signature, fuzz_write, &output, 0u,
                                                &response_length);
            fuzz_check(status == (finish_status == COMPOSITE_EAT_OK ? COMPOSITE_EAT_BUFFER_TOO_SMALL
                                                                    : finish_status));
            fuzz_check(output.calls == 0u);
            break;
        case 4u:
            output.fail_after = 0u;
            status = composite_eat_write_signing_input(&prepared, fuzz_write, &output);
            fuzz_check(status == (ready ? COMPOSITE_EAT_WRITE_ERROR : COMPOSITE_EAT_STATE_ERROR));
            signed_input = false;
            break;
        case 5u:
            output.fail_after = 0u;
            status = composite_eat_finish_write(&prepared, signature, fuzz_write, &output,
                                                sizeof(response), &response_length);
            fuzz_check(status == (finish_status == COMPOSITE_EAT_OK ? COMPOSITE_EAT_WRITE_ERROR
                                                                    : finish_status));
            fuzz_check(response_length == 0u);
            break;
        case 6u:
            composite_eat_clear(&workspace, &prepared);
            fuzz_check(fuzz_is_zero(&workspace, sizeof(workspace)));
            fuzz_check(fuzz_is_zero(&prepared, sizeof(prepared)));
            ready = false;
            signed_input = false;
            break;
        case 7u:
            fuzz_check(composite_eat_prepare(&invalid_request, &evidence, &identity, thumbprint,
                                             &workspace, &prepared) == COMPOSITE_EAT_BAD_ARGUMENT);
            fuzz_check(fuzz_is_zero(&workspace, sizeof(workspace)));
            fuzz_check(fuzz_is_zero(&prepared, sizeof(prepared)));
            ready = false;
            signed_input = false;
            break;
        case 8u:
            fuzz_check(composite_eat_write_signing_input(&prepared, NULL, NULL) ==
                       COMPOSITE_EAT_BAD_ARGUMENT);
            break;
        }
    }
    composite_eat_clear(&workspace, &prepared);
    return 0;
}
