// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "test_check.h"
#include <string.h>

#include "software_platform.h"

struct test_context {
    const struct composite_eat_evidence_snapshot *evidence;
    const struct composite_eat_reference_evidence *reference_evidence;
    size_t reference_evidence_count;
    const struct composite_eat_attestation_identity *identity;
    size_t evidence_begin_count;
    size_t evidence_end_count;
    size_t identity_begin_count;
    size_t identity_end_count;
    size_t hash_start_count;
    size_t hash_finish_count;
    size_t hash_abort_count;
    size_t sign_count;
    size_t verify_count;
    bool fail_hash_update;
    bool fail_verify;
};

static int begin_snapshot(void *context, void **snapshot_handle,
                          struct composite_eat_evidence_snapshot *evidence,
                          const struct composite_eat_reference_evidence **reference_evidence,
                          size_t *reference_evidence_count) {
    struct test_context *test = context;

    ++test->evidence_begin_count;
    *snapshot_handle = test;
    *evidence = *test->evidence;
    *reference_evidence = test->reference_evidence;
    *reference_evidence_count = test->reference_evidence_count;
    return 0;
}

static void end_snapshot(void *context, void *snapshot_handle) {
    struct test_context *test = context;

    TEST_CHECK(snapshot_handle == test);
    ++test->evidence_end_count;
}

static int approve_test_evidence(void *context,
                                 const struct tcg_concise_evidence_document *document) {
    return (context == document) ? 0 : -1;
}

static int reject_test_evidence(void *context,
                                const struct tcg_concise_evidence_document *document) {
    (void)context;
    (void)document;
    return -1;
}

static int begin_identity(void *context, void **identity_handle,
                          struct composite_eat_attestation_identity *identity) {
    struct test_context *test = context;

    TEST_CHECK(test->evidence_begin_count == (test->identity_begin_count + 1u));
    ++test->identity_begin_count;
    *identity_handle = test;
    *identity = *test->identity;
    return 0;
}

static int hash_start(void *context, void **hash_handle) {
    struct test_context *test = context;

    ++test->hash_start_count;
    *hash_handle = test;
    return 0;
}

static int hash_update(void *context, void *hash_handle, const uint8_t *data, size_t length) {
    struct test_context *test = context;

    TEST_CHECK(hash_handle == context);
    TEST_CHECK(data != NULL);
    TEST_CHECK(length != 0u);
    if (test->fail_hash_update) {
        test->fail_hash_update = false;
        return -1;
    }
    return 0;
}

static int hash_finish(void *context, void *hash_handle,
                       uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH]) {
    struct test_context *test = context;

    TEST_CHECK(hash_handle == test);
    ++test->hash_finish_count;
    memset(digest, 0x5a, COMPOSITE_EAT_SHA384_LENGTH);
    return 0;
}

static void hash_abort(void *context, void *hash_handle) {
    struct test_context *test = context;

    TEST_CHECK(hash_handle == test);
    ++test->hash_abort_count;
}

static int sign_digest(void *context, void *identity_handle,
                       const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                       uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
    struct test_context *test = context;

    TEST_CHECK(identity_handle == test);
    TEST_CHECK(digest[0] == 0x5au);
    ++test->sign_count;
    memset(signature, 0xa5, COMPOSITE_EAT_ES384_SIGNATURE_LENGTH);
    return 0;
}

static int verify_signature(void *context, void *identity_handle,
                            const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                            const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
    struct test_context *test = context;

    TEST_CHECK(identity_handle == test);
    TEST_CHECK(digest[0] == 0x5au);
    TEST_CHECK(signature[0] == 0xa5u);
    ++test->verify_count;
    return test->fail_verify ? -1 : 0;
}

static void end_identity(void *context, void *identity_handle) {
    struct test_context *test = context;

    TEST_CHECK(identity_handle == test);
    ++test->identity_end_count;
}

int main(void) {
    static const uint8_t ueid[] = {1, 1, 1, 1, 1, 1, 1};
    static const uint8_t profile[] = COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI;
    static const uint8_t wrong_profile[] = "https://example.invalid/profile";
    static const uint8_t class_id[] = "reference-rot";
    static const uint8_t certificate_bytes[] = {0x30, 0x00};
    uint8_t measurement_digest[TCG_CONCISE_EVIDENCE_SHA384_LENGTH] = {0};
    uint8_t evidence_bytes[256];
    size_t evidence_length = 0u;
    struct tcg_concise_evidence_digest ce_digest = {
        {TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384, {0}},
        {measurement_digest, sizeof(measurement_digest)}};
    struct tcg_concise_evidence_measurement measurement = {
        .has_key = true,
        .key = {TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT, {.uint_value = 0u}},
        .values = {&ce_digest, 1u, false, {0}, false, {0}},
    };
    struct tcg_concise_evidence_triple triple = {
        .environment =
            {
                .has_class = true,
                .class_info =
                    {
                        .has_class_id = true,
                        .class_id = {TCG_CONCISE_EVIDENCE_TAGGED_BYTES,
                                     {class_id, sizeof(class_id) - 1u}},
                    },
            },
        .measurements = &measurement,
        .measurement_count = 1u,
    };
    struct tcg_concise_evidence_document document = {&triple, 1u};
    const struct composite_eat_profile_evidence_policy policy = {
        .max_triples = 1u,
        .max_measurements_per_triple = 1u,
        .max_digests_per_measurement = 1u,
        .max_identifier_length = 64u,
        .max_text_length = 64u,
        .max_encoded_length = sizeof(evidence_bytes),
        .allowed_mkey_types = COMPOSITE_EAT_PROFILE_MKEY_UINT,
        .allowed_algorithms = COMPOSITE_EAT_PROFILE_ALGORITHM_SHA384,
        .require_measurement_key = true,
        .require_class = true,
        .require_class_id = true,
    };
    struct composite_eat_reference_evidence reference_evidence = {&document, &policy, &document,
                                                                  approve_test_evidence};
    struct composite_eat_generation_request request = {0};
    struct composite_eat_local_evidence local_evidence = {
        .content_format = COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT,
    };
    struct composite_eat_evidence_snapshot evidence = {
        .ueid = {ueid, sizeof(ueid)},
        .profile = {profile, sizeof(profile) - 1u},
        .local_evidence = &local_evidence,
        .local_evidence_count = 1u,
    };
    struct composite_eat_der_certificate certificate = {certificate_bytes,
                                                        sizeof(certificate_bytes)};
    struct composite_eat_attestation_identity identity = {&certificate, 1u};
    struct test_context context = {
        .evidence = &evidence,
        .reference_evidence = &reference_evidence,
        .reference_evidence_count = 1u,
        .identity = &identity,
    };
    const struct example_evidence_provider evidence_provider = {
        .context = &context,
        .begin_snapshot = begin_snapshot,
        .end_snapshot = end_snapshot,
    };
    const struct example_attestation_provider attestation_provider = {
        .context = &context,
        .begin_identity = begin_identity,
        .hash_start_sha384 = hash_start,
        .hash_update = hash_update,
        .hash_finish = hash_finish,
        .hash_abort = hash_abort,
        .sign_es384_digest = sign_digest,
        .verify_es384_digest_signature = verify_signature,
        .end_identity = end_identity,
    };
    struct composite_eat_workspace workspace;
    uint8_t response[1024];
    size_t response_length = 0u;
    size_t index;

    request.version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    request.nonce_length = COMPOSITE_EAT_NONCE_LENGTH;
    memcpy(request.records[0].environment, "env.device.0", sizeof("env.device.0") - 1u);
    request.records[0].environment_length = sizeof("env.device.0") - 1u;
    request.record_count = 1u;
    TEST_CHECK(tcg_concise_evidence_encode(&document, evidence_bytes, sizeof(evidence_bytes),
                                           &evidence_length) == TCG_CONCISE_EVIDENCE_OK);
    local_evidence.encoded = (struct composite_eat_buffer){evidence_bytes, evidence_length};

    TEST_CHECK(example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
                                              &workspace, response, sizeof(response),
                                              &response_length) == COMPOSITE_EAT_OK);
    TEST_CHECK(response_length != 0u);
    TEST_CHECK(response[0] == 0xd8u);
    TEST_CHECK(context.evidence_begin_count == 1u);
    TEST_CHECK(context.evidence_end_count == 1u);
    TEST_CHECK(context.identity_begin_count == 1u);
    TEST_CHECK(context.identity_end_count == 1u);
    TEST_CHECK(context.hash_start_count == 2u);
    TEST_CHECK(context.hash_finish_count == 2u);
    TEST_CHECK(context.sign_count == 1u);
    TEST_CHECK(context.verify_count == 1u);
    for (index = 0u; index < sizeof(workspace); ++index) {
        TEST_CHECK(((const uint8_t *)&workspace)[index] == 0u);
    }

    request.version = 0u;
    response_length = sizeof(response);
    TEST_CHECK(example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
                                              &workspace, response, sizeof(response),
                                              &response_length) == COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(response_length == 0u);
    TEST_CHECK(context.evidence_begin_count == 1u);
    TEST_CHECK(context.identity_begin_count == 1u);

    request.version = COMPOSITE_EAT_GENERATION_REQUEST_VERSION;
    context.fail_hash_update = true;
    TEST_CHECK(example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
                                              &workspace, response, sizeof(response),
                                              &response_length) == COMPOSITE_EAT_STATE_ERROR);
    TEST_CHECK(response_length == 0u);
    TEST_CHECK(context.evidence_begin_count == 2u);
    TEST_CHECK(context.evidence_end_count == 2u);
    TEST_CHECK(context.identity_begin_count == 2u);
    TEST_CHECK(context.identity_end_count == 2u);
    TEST_CHECK(context.hash_start_count == 3u);
    TEST_CHECK(context.hash_finish_count == 2u);
    TEST_CHECK(context.hash_abort_count == 1u);
    TEST_CHECK(context.sign_count == 1u);
    for (index = 0u; index < sizeof(workspace); ++index) {
        TEST_CHECK(((const uint8_t *)&workspace)[index] == 0u);
    }

    memset(&workspace, 0xa5, sizeof(workspace));
    response_length = sizeof(response);
    TEST_CHECK(example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
                                              &workspace, NULL, 1u,
                                              &response_length) == COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(response_length == 0u);
    for (index = 0u; index < sizeof(workspace); ++index) {
        TEST_CHECK(((const uint8_t *)&workspace)[index] == 0u);
    }

    context.fail_verify = true;
    response_length = sizeof(response);
    TEST_CHECK(example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
                                              &workspace, response, sizeof(response),
                                              &response_length) == COMPOSITE_EAT_STATE_ERROR);
    TEST_CHECK(response_length == 0u);
    TEST_CHECK(context.evidence_begin_count == 3u);
    TEST_CHECK(context.evidence_end_count == 3u);
    TEST_CHECK(context.identity_begin_count == 3u);
    TEST_CHECK(context.identity_end_count == 3u);
    TEST_CHECK(context.hash_start_count == 5u);
    TEST_CHECK(context.hash_finish_count == 4u);
    TEST_CHECK(context.hash_abort_count == 1u);
    TEST_CHECK(context.sign_count == 2u);
    TEST_CHECK(context.verify_count == 2u);
    for (index = 0u; index < sizeof(workspace); ++index) {
        TEST_CHECK(((const uint8_t *)&workspace)[index] == 0u);
    }
    context.fail_verify = false;

    reference_evidence.platform_policy_validate = reject_test_evidence;
    TEST_CHECK(example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
                                              &workspace, response, sizeof(response),
                                              &response_length) == COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(response_length == 0u);
    TEST_CHECK(context.evidence_begin_count == 4u);
    TEST_CHECK(context.evidence_end_count == 4u);
    TEST_CHECK(context.identity_begin_count == 3u);
    reference_evidence.platform_policy_validate = approve_test_evidence;

    evidence.profile = (struct composite_eat_buffer){wrong_profile, sizeof(wrong_profile) - 1u};
    TEST_CHECK(example_generate_composite_eat(&attestation_provider, &evidence_provider, &request,
                                              &workspace, response, sizeof(response),
                                              &response_length) == COMPOSITE_EAT_BAD_ARGUMENT);
    TEST_CHECK(context.evidence_begin_count == 5u);
    TEST_CHECK(context.evidence_end_count == 5u);
    TEST_CHECK(context.identity_begin_count == 3u);
    evidence.profile = (struct composite_eat_buffer){profile, sizeof(profile) - 1u};
    return 0;
}
