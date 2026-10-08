// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "test_check.h"
#include <stdio.h>
#include <string.h>

#include "composite_eat/profile_evidence.h"

struct output {
    uint8_t *data;
    size_t capacity;
    size_t length;
};

static int write_output(void *context, const uint8_t *data, size_t length) {
    struct output *output = context;

    if ((output == NULL) || ((data == NULL) && (length != 0u)) ||
        (output->length > output->capacity) || ((output->capacity - output->length) < length)) {
        return -1;
    }
    memcpy(&output->data[output->length], data, length);
    output->length += length;
    return 0;
}

static int fail_write(void *context, const uint8_t *data, size_t length) {
    (void)context;
    (void)data;
    (void)length;
    return -1;
}

static struct tcg_concise_evidence_environment make_environment(const uint8_t *class_id,
                                                                size_t class_id_length,
                                                                const uint8_t *model,
                                                                size_t model_length) {
    static const uint8_t vendor[] = "Example Vendor";
    struct tcg_concise_evidence_environment environment = {
        .has_class = true,
        .class_info =
            {
                .has_class_id = true,
                .class_id = {TCG_CONCISE_EVIDENCE_TAGGED_BYTES, {class_id, class_id_length}},
                .has_vendor = true,
                .vendor = {vendor, sizeof(vendor) - 1u},
                .has_model = true,
                .model = {model, model_length},
            },
    };

    return environment;
}

static void test_extended_forms(void) {
    static const uint8_t rot_class[] = "generic-rot";
    static const uint8_t rom_class[] = "generic-rom";
    static const uint8_t rot_model[] = "Generic RoT";
    static const uint8_t rom_model[] = "Generic ROM";
    static const uint8_t component_key[] = "component-0";
    static const uint8_t uuid[16] = {0x37};
    static const uint8_t oid[] = {0x2b, 0x06, 0x01};
    static const uint8_t algorithm_name[] = "custom-hash";
    static const uint8_t custom_digest[] = {1u, 2u, 3u};
    uint8_t sha256[TCG_CONCISE_EVIDENCE_SHA256_LENGTH] = {0};
    uint8_t sha512[TCG_CONCISE_EVIDENCE_SHA512_LENGTH] = {0};
    struct tcg_concise_evidence_digest standard_digests[] = {
        {{TCG_CONCISE_EVIDENCE_ALGORITHM_SHA256, {0}}, {sha256, sizeof(sha256)}},
        {{TCG_CONCISE_EVIDENCE_ALGORITHM_SHA512, {0}}, {sha512, sizeof(sha512)}},
    };
    struct tcg_concise_evidence_digest custom_digests[] = {
        {{TCG_CONCISE_EVIDENCE_ALGORITHM_INTEGER, {.integer = -16}},
         {custom_digest, sizeof(custom_digest)}},
        {{TCG_CONCISE_EVIDENCE_ALGORITHM_TEXT,
          {.text = {algorithm_name, sizeof(algorithm_name) - 1u}}},
         {custom_digest, sizeof(custom_digest)}},
    };
    struct tcg_concise_evidence_measurement measurements[3] = {0};
    struct tcg_concise_evidence_triple triples[2] = {0};
    struct tcg_concise_evidence_document document = {triples, 2u};
    const struct composite_eat_profile_evidence_policy policy = {
        .max_triples = 2u,
        .max_measurements_per_triple = 2u,
        .max_digests_per_measurement = 2u,
        .max_identifier_length = 64u,
        .max_text_length = 64u,
        .max_encoded_length = 2048u,
        .allowed_mkey_types = COMPOSITE_EAT_PROFILE_MKEY_UINT | COMPOSITE_EAT_PROFILE_MKEY_TEXT |
                              COMPOSITE_EAT_PROFILE_MKEY_UUID | COMPOSITE_EAT_PROFILE_MKEY_OID,
        .allowed_algorithms =
            COMPOSITE_EAT_PROFILE_ALGORITHM_SHA256 | COMPOSITE_EAT_PROFILE_ALGORITHM_SHA512 |
            COMPOSITE_EAT_PROFILE_ALGORITHM_INTEGER | COMPOSITE_EAT_PROFILE_ALGORITHM_TEXT,
        .require_measurement_key = true,
        .require_class = true,
        .require_class_id = true,
        .require_vendor = true,
        .require_model = true,
        .allow_flags = true,
    };
    uint8_t encoded[2048];
    size_t encoded_length = 0u;

    measurements[0].has_key = true;
    measurements[0].key.type = TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT;
    measurements[0].key.value.uint_value = 0u;
    measurements[0].values.digests = &standard_digests[0];
    measurements[0].values.digest_count = 1u;
    measurements[1].has_key = true;
    measurements[1].key.type = TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT;
    measurements[1].key.value.text =
        (struct tcg_concise_evidence_text){component_key, sizeof(component_key) - 1u};
    measurements[1].values.digests = &standard_digests[1];
    measurements[1].values.digest_count = 1u;
    measurements[1].values.has_flags = true;
    measurements[1].values.flags.has_is_integrity_protected = true;
    measurements[1].values.flags.is_integrity_protected = true;
    measurements[1].values.flags.has_is_immutable = true;
    measurements[1].values.flags.is_immutable = true;
    measurements[1].values.flags.has_is_tcb = true;
    measurements[1].values.flags.is_tcb = true;
    measurements[2].has_key = true;
    measurements[2].key.type = TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID;
    measurements[2].key.value.bytes = (struct tcg_concise_evidence_bytes){uuid, sizeof(uuid)};
    measurements[2].values.digests = custom_digests;
    measurements[2].values.digest_count = 2u;

    triples[0].environment =
        make_environment(rot_class, sizeof(rot_class) - 1u, rot_model, sizeof(rot_model) - 1u);
    triples[0].measurements = measurements;
    triples[0].measurement_count = 2u;
    triples[1].environment =
        make_environment(rom_class, sizeof(rom_class) - 1u, rom_model, sizeof(rom_model) - 1u);
    triples[1].measurements = &measurements[2];
    triples[1].measurement_count = 1u;

    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_OK);
    TEST_CHECK(tcg_concise_evidence_encode(&document, encoded, sizeof(encoded), &encoded_length) ==
               TCG_CONCISE_EVIDENCE_OK);
    TEST_CHECK(encoded_length > 0u);

    {
        struct composite_eat_profile_evidence_policy limited_policy = policy;

        limited_policy.max_triples = 1u;
        TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &limited_policy,
                                                                 &encoded_length) ==
                   COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED);
    }

    measurements[2].key.type = TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID;
    measurements[2].key.value.bytes = (struct tcg_concise_evidence_bytes){oid, sizeof(oid)};
    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_OK);
}

int main(int argc, char **argv) {
    static const uint8_t expected[] = {
        0xa1, 0x00, 0xa1, 0x00, 0x81, 0x82, 0xa1, 0x00, 0xa3, 0x00, 0xd9, 0x02, 0x30, 0x44,
        0x01, 0x02, 0x03, 0x04, 0x01, 0x6e, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20,
        0x56, 0x65, 0x6e, 0x64, 0x6f, 0x72, 0x02, 0x6d, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x20, 0x4d, 0x6f, 0x64, 0x65, 0x6c, 0x82, 0xa2, 0x00, 0x00, 0x01, 0xa1, 0x02,
        0x81, 0x82, 0x67, 0x73, 0x68, 0x61, 0x2d, 0x32, 0x35, 0x36, 0x58, 0x20, 0x25, 0x25,
        0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25,
        0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25, 0x25,
        0x25, 0x25, 0xa2, 0x00, 0x01, 0x01, 0xa1, 0x02, 0x81, 0x82, 0x67, 0x73, 0x68, 0x61,
        0x2d, 0x33, 0x38, 0x34, 0x58, 0x30, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
        0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
        0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
        0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
    };
    static const uint8_t class_id[] = {1u, 2u, 3u, 4u};
    static const uint8_t vendor[] = "Example Vendor";
    static const uint8_t model[] = "Example Model";
    uint8_t sha256[TCG_CONCISE_EVIDENCE_SHA256_LENGTH];
    uint8_t sha384[TCG_CONCISE_EVIDENCE_SHA384_LENGTH];
    struct tcg_concise_evidence_digest digests[2];
    struct tcg_concise_evidence_measurement measurements[2] = {0};
    struct tcg_concise_evidence_triple triple = {0};
    struct tcg_concise_evidence_document document = {&triple, 1u};
    const struct composite_eat_profile_evidence_policy policy = {
        .max_triples = 1u,
        .max_measurements_per_triple = 2u,
        .max_digests_per_measurement = 1u,
        .max_identifier_length = 64u,
        .max_text_length = 64u,
        .max_encoded_length = sizeof(expected),
        .allowed_mkey_types = COMPOSITE_EAT_PROFILE_MKEY_UINT,
        .allowed_algorithms =
            COMPOSITE_EAT_PROFILE_ALGORITHM_SHA256 | COMPOSITE_EAT_PROFILE_ALGORITHM_SHA384,
        .require_measurement_key = true,
        .require_class = true,
        .require_class_id = true,
        .require_vendor = true,
        .require_model = true,
    };
    uint8_t encoded[sizeof(expected)];
    uint8_t streamed[sizeof(expected)];
    struct output output = {streamed, sizeof(streamed), 0u};
    size_t encoded_length = 0u;

    memset(sha256, 0x25, sizeof(sha256));
    memset(sha384, 0x38, sizeof(sha384));
    digests[0] = (struct tcg_concise_evidence_digest){{TCG_CONCISE_EVIDENCE_ALGORITHM_SHA256, {0}},
                                                      {sha256, sizeof(sha256)}};
    digests[1] = (struct tcg_concise_evidence_digest){{TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384, {0}},
                                                      {sha384, sizeof(sha384)}};
    measurements[0].has_key = true;
    measurements[0].key.type = TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT;
    measurements[0].key.value.uint_value = 0u;
    measurements[0].values.digests = &digests[0];
    measurements[0].values.digest_count = 1u;
    measurements[1].has_key = true;
    measurements[1].key.type = TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UINT;
    measurements[1].key.value.uint_value = 1u;
    measurements[1].values.digests = &digests[1];
    measurements[1].values.digest_count = 1u;
    triple.environment.has_class = true;
    triple.environment.class_info.has_class_id = true;
    triple.environment.class_info.class_id = (struct tcg_concise_evidence_tagged_id){
        TCG_CONCISE_EVIDENCE_TAGGED_BYTES, {class_id, sizeof(class_id)}};
    triple.environment.class_info.has_vendor = true;
    triple.environment.class_info.vendor =
        (struct tcg_concise_evidence_text){vendor, sizeof(vendor) - 1u};
    triple.environment.class_info.has_model = true;
    triple.environment.class_info.model =
        (struct tcg_concise_evidence_text){model, sizeof(model) - 1u};
    triple.measurements = measurements;
    triple.measurement_count = 2u;

    TEST_CHECK(COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT == 10571u);
    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_OK);
    TEST_CHECK(encoded_length == sizeof(expected));
    TEST_CHECK(tcg_concise_evidence_encode(&document, encoded, sizeof(encoded), &encoded_length) ==
               TCG_CONCISE_EVIDENCE_OK);
    TEST_CHECK(memcmp(encoded, expected, sizeof(expected)) == 0);
    TEST_CHECK(
        tcg_concise_evidence_encode(&document, encoded, sizeof(encoded) - 1u, &encoded_length) ==
        TCG_CONCISE_EVIDENCE_BUFFER_TOO_SMALL);
    TEST_CHECK(encoded_length == sizeof(expected));
    TEST_CHECK(tcg_concise_evidence_encode_write(&document, write_output, &output, sizeof(streamed),
                                                 &encoded_length) == TCG_CONCISE_EVIDENCE_OK);
    TEST_CHECK(output.length == sizeof(expected));
    TEST_CHECK(memcmp(streamed, expected, sizeof(expected)) == 0);
    TEST_CHECK(tcg_concise_evidence_encode_write(&document, fail_write, NULL, sizeof(expected),
                                                 &encoded_length) ==
               TCG_CONCISE_EVIDENCE_WRITE_ERROR);

    {
        struct composite_eat_profile_evidence_policy limited_policy = policy;

        limited_policy.max_measurements_per_triple = 1u;
        TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &limited_policy,
                                                                 &encoded_length) ==
                   COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED);
        limited_policy = policy;
        limited_policy.max_encoded_length = sizeof(expected) - 1u;
        TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &limited_policy,
                                                                 &encoded_length) ==
                   COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED);
        limited_policy = policy;
        limited_policy.max_identifier_length = sizeof(class_id) - 1u;
        TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &limited_policy,
                                                                 &encoded_length) ==
                   COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR);
        limited_policy = policy;
        limited_policy.max_text_length = sizeof(vendor) - 2u;
        TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &limited_policy,
                                                                 &encoded_length) ==
                   COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR);
    }

    measurements[0].values.digest_count = 2u;
    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED);
    measurements[0].values.digest_count = 1u;

    measurements[0].values.has_flags = true;
    measurements[0].values.flags.has_is_tcb = true;
    measurements[0].values.flags.is_tcb = true;
    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR);
    measurements[0].values.flags.has_is_tcb = false;
    TEST_CHECK(tcg_concise_evidence_validate(&document) == TCG_CONCISE_EVIDENCE_BAD_ARGUMENT);
    measurements[0].values.has_flags = false;

    measurements[0].values.has_name = true;
    measurements[0].values.name = (struct tcg_concise_evidence_text){vendor, sizeof(vendor) - 1u};
    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR);
    measurements[0].values.has_name = false;

    measurements[1].key.value.uint_value = 0u;
    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR);
    measurements[1].key.value.uint_value = 1u;
    digests[1].value.length--;
    TEST_CHECK(composite_eat_profile_validate_local_evidence(&document, &policy, &encoded_length) ==
               COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR);

    test_extended_forms();

    if (argc == 2) {
        FILE *output_file = fopen(argv[1], "wb");
        size_t written;
        int close_status;

        TEST_CHECK(output_file != NULL);
        written = fwrite(streamed, 1u, sizeof(streamed), output_file);
        close_status = fclose(output_file);
        TEST_CHECK(written == sizeof(streamed));
        TEST_CHECK(close_status == 0);
    }
    return 0;
}
