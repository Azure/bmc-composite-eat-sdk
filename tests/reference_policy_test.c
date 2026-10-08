// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "test_check.h"
#include <string.h>

#include "composite_eat/reference_policy.h"

static int write_unused(void *context, composite_eat_write write, void *write_context) {
    (void)context;
    (void)write;
    (void)write_context;
    return -1;
}

struct test_platform_policy {
    const uint8_t *class_id;
    size_t class_id_length;
    uint64_t measurement_key;
};

static int validate_platform_policy(void *context,
                                    const struct tcg_concise_evidence_document *document) {
    const struct test_platform_policy *policy = context;
    const struct tcg_concise_evidence_triple *triple;
    const struct tcg_concise_evidence_measurement *measurement;

    if ((policy == NULL) || (document == NULL) || (document->evidence_triple_count != 1u)) {
        return -1;
    }
    triple = &document->evidence_triples[0];
    if (!triple->environment.has_class || !triple->environment.class_info.has_class_id ||
        (triple->environment.class_info.class_id.type != TCG_CONCISE_EVIDENCE_TAGGED_BYTES) ||
        (triple->environment.class_info.class_id.value.length != policy->class_id_length) ||
        (memcmp(triple->environment.class_info.class_id.value.data, policy->class_id,
                policy->class_id_length) != 0) ||
        (triple->measurement_count != 1u)) {
        return -1;
    }
    measurement = &triple->measurements[0];
    return (!measurement->has_key ||
            (measurement->key.type != TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT) ||
            (measurement->key.value.uint_value != policy->measurement_key))
               ? -1
               : 0;
}

int main(void) {
    static const uint8_t profile[] = COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI;
    static const uint8_t wrong_profile[] =
        "https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat-00/";
    static const uint8_t future_profile[] =
        "https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat-01/";
    static const uint8_t aspeed_profile[] =
        "https://github.com/aspeedtech-bmc/profile/composite_eat";
    static const uint8_t ueid[] = {1u, 1u, 1u, 1u, 1u, 1u, 1u};
    static const uint8_t class_id[] = "reference-rot";
    static const uint8_t unauthorized_class_id[] = "unauthorized-rot";
    static const uint8_t arbitrary_cbor[] = {0xa0u};
    uint8_t digest[TCG_CONCISE_EVIDENCE_SHA384_LENGTH] = {0};
    uint8_t encoded[256];
    size_t encoded_length = 0u;
    struct tcg_concise_evidence_digest ce_digest = {{TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384, {0}},
                                                    {digest, sizeof(digest)}};
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
        .max_measurements_per_triple = 2u,
        .max_digests_per_measurement = 1u,
        .max_identifier_length = 64u,
        .max_text_length = 64u,
        .max_encoded_length = sizeof(encoded),
        .allowed_mkey_types = COMPOSITE_EAT_PROFILE_MKEY_UINT,
        .allowed_algorithms = COMPOSITE_EAT_PROFILE_ALGORITHM_SHA384,
        .require_measurement_key = true,
        .require_class = true,
        .require_class_id = true,
    };
    struct test_platform_policy platform_policy = {class_id, sizeof(class_id) - 1u, 0u};
    struct composite_eat_local_evidence local = {0};
    struct composite_eat_evidence_snapshot snapshot = {
        .ueid = {ueid, sizeof(ueid)},
        .profile = {profile, sizeof(profile) - 1u},
        .local_evidence = &local,
        .local_evidence_count = 1u,
    };
    struct composite_eat_reference_evidence reference = {&document, &policy, &platform_policy,
                                                         validate_platform_policy};

    TEST_CHECK(tcg_concise_evidence_encode(&document, encoded, sizeof(encoded), &encoded_length) ==
               TCG_CONCISE_EVIDENCE_OK);
    local.content_format = COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT;
    local.encoded = (struct composite_eat_buffer){encoded, encoded_length};
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_OK);

    triple.environment.class_info.class_id.value = (struct tcg_concise_evidence_bytes){
        unauthorized_class_id, sizeof(unauthorized_class_id) - 1u};
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_PLATFORM_POLICY_ERROR);
    triple.environment.class_info.class_id.value =
        (struct tcg_concise_evidence_bytes){class_id, sizeof(class_id) - 1u};

    measurement.key.value.uint_value = 1u;
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_PLATFORM_POLICY_ERROR);
    measurement.key.value.uint_value = 0u;

    reference.platform_policy_validate = NULL;
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT);
    reference.platform_policy_validate = validate_platform_policy;

    {
        struct composite_eat_local_evidence local_entries[] = {local, local};
        struct composite_eat_reference_evidence reference_entries[] = {reference, reference};

        snapshot.local_evidence = local_entries;
        snapshot.local_evidence_count = 2u;
        TEST_CHECK(composite_eat_reference_policy_validate_snapshot(
                       &snapshot, reference_entries, 2u) == COMPOSITE_EAT_REFERENCE_POLICY_OK);
        reference_entries[1].platform_policy_validate = NULL;
        TEST_CHECK(
            composite_eat_reference_policy_validate_snapshot(&snapshot, reference_entries, 2u) ==
            COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT);
        snapshot.local_evidence = &local;
        snapshot.local_evidence_count = 1u;
    }

    snapshot.profile = (struct composite_eat_buffer){wrong_profile, sizeof(wrong_profile) - 1u};
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_PROFILE_ERROR);
    snapshot.profile = (struct composite_eat_buffer){aspeed_profile, sizeof(aspeed_profile) - 1u};
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_PROFILE_ERROR);
    snapshot.profile = (struct composite_eat_buffer){future_profile, sizeof(future_profile) - 1u};
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_PROFILE_ERROR);
    snapshot.profile = (struct composite_eat_buffer){profile, sizeof(profile) - 1u};

    local.content_format = 60u;
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_CONTENT_FORMAT_ERROR);
    local.content_format = COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT;

    local.encoded = (struct composite_eat_buffer){arbitrary_cbor, sizeof(arbitrary_cbor)};
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_SNAPSHOT_MISMATCH);
    local.encoded = (struct composite_eat_buffer){encoded, encoded_length};

    encoded[encoded_length - 1u] ^= 1u;
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_SNAPSHOT_MISMATCH);
    encoded[encoded_length - 1u] ^= 1u;

    ce_digest.value.length--;
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_SCHEMA_ERROR);
    ce_digest.value.length++;

    ce_digest.algorithm.type = TCG_CONCISE_EVIDENCE_ALGORITHM_SHA256;
    ce_digest.value.length = TCG_CONCISE_EVIDENCE_SHA256_LENGTH;
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_PLATFORM_POLICY_ERROR);
    ce_digest.algorithm.type = TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384;
    ce_digest.value.length = TCG_CONCISE_EVIDENCE_SHA384_LENGTH;

    {
        struct tcg_concise_evidence_measurement duplicates[] = {measurement, measurement};

        triple.measurements = duplicates;
        triple.measurement_count = 2u;
        TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
                   COMPOSITE_EAT_REFERENCE_POLICY_PLATFORM_POLICY_ERROR);
        triple.measurements = &measurement;
        triple.measurement_count = 1u;
    }

    local.encoded = (struct composite_eat_buffer){0};
    local.encoded_length = encoded_length;
    local.write = write_unused;
    TEST_CHECK(composite_eat_reference_policy_validate_snapshot(&snapshot, &reference, 1u) ==
               COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT);
    return 0;
}
