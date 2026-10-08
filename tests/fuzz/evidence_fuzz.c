// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
#include "composite_eat/profile_evidence.h"
#include "fuzz_helpers.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct fuzz_input input = {data, size, 0u};
    uint8_t identifier[33];
    uint8_t digest_bytes[64];
    uint8_t text[32];
    uint8_t encoded[4096];
    uint8_t streamed[4096];
    struct tcg_concise_evidence_digest digests[2] = {0};
    struct tcg_concise_evidence_measurement measurements[2] = {0};
    struct tcg_concise_evidence_triple triples[2] = {0};
    struct tcg_concise_evidence_document document = {triples, 1u + fuzz_byte(&input) % 2u};
    struct composite_eat_profile_evidence_policy policy = {
        .max_triples = 2u,
        .max_measurements_per_triple = 2u,
        .max_digests_per_measurement = 2u,
        .max_identifier_length = sizeof(identifier),
        .max_text_length = sizeof(text),
        .max_encoded_length = sizeof(encoded),
        .allowed_mkey_types = 15u,
        .allowed_algorithms = 31u,
        .allow_flags = true,
        .allow_name = true,
    };
    size_t required = 0u;
    size_t encoded_length = 0u;
    size_t policy_length = 0u;

    triples[0].environment.has_class = (fuzz_byte(&input) & 1u) == 0u;
    triples[0].environment.class_info.has_class_id = true;
    triples[0].environment.class_info.class_id.type =
        (enum tcg_concise_evidence_tagged_id_type)(fuzz_byte(&input) % 6u);
    triples[0].environment.class_info.class_id.value = (struct tcg_concise_evidence_bytes){
        identifier, 1u + fuzz_byte(&input) % sizeof(identifier)};
    triples[0].measurement_count = 1u + fuzz_byte(&input) % 2u;
    triples[0].measurements = measurements;
    for (size_t index = 0u; index < 2u; ++index) {
        size_t digest_length;
        digests[index].algorithm.type =
            (enum tcg_concise_evidence_algorithm_type)(fuzz_byte(&input) % 7u);
        digests[index].algorithm.value.integer = (int8_t)fuzz_byte(&input);
        if (digests[index].algorithm.type == TCG_CONCISE_EVIDENCE_ALGORITHM_TEXT) {
            digests[index].algorithm.value.text =
                (struct tcg_concise_evidence_text){text, fuzz_byte(&input) % (sizeof(text) + 1u)};
        }
        digest_length = digests[index].algorithm.type == TCG_CONCISE_EVIDENCE_ALGORITHM_SHA384 ? 48u
                        : digests[index].algorithm.type == TCG_CONCISE_EVIDENCE_ALGORITHM_SHA512
                            ? 64u
                            : 32u;
        if ((fuzz_byte(&input) & 1u) != 0u) {
            digest_length = fuzz_byte(&input) % (sizeof(digest_bytes) + 1u);
        }
        digests[index].value = (struct tcg_concise_evidence_bytes){digest_bytes, digest_length};
        measurements[index].has_key = (fuzz_byte(&input) & 1u) == 0u;
        measurements[index].key.type =
            (enum tcg_concise_evidence_measured_element_type)(fuzz_byte(&input) % 6u);
        measurements[index].key.value.uint_value = fuzz_byte(&input);
        if (measurements[index].key.type == TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_TEXT) {
            measurements[index].key.value.text =
                (struct tcg_concise_evidence_text){text, fuzz_byte(&input) % (sizeof(text) + 1u)};
        } else if (measurements[index].key.type == TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_UUID ||
                   measurements[index].key.type == TCG_CONCISE_EVIDENCE_MEASURED_ELEMENT_OID) {
            measurements[index].key.value.bytes = (struct tcg_concise_evidence_bytes){
                identifier, fuzz_byte(&input) % (sizeof(identifier) + 1u)};
        }
        measurements[index].values.digests = digests;
        measurements[index].values.digest_count = 1u + fuzz_byte(&input) % 2u;
        measurements[index].values.has_name = (fuzz_byte(&input) & 1u) != 0u;
        measurements[index].values.name =
            (struct tcg_concise_evidence_text){text, fuzz_byte(&input) % (sizeof(text) + 1u)};
        measurements[index].values.has_flags = (fuzz_byte(&input) & 1u) != 0u;
        measurements[index].values.flags.has_is_tcb = (fuzz_byte(&input) & 1u) != 0u;
        measurements[index].values.flags.is_tcb = (fuzz_byte(&input) & 1u) != 0u;
    }
    triples[1] = triples[0];
    policy.allowed_algorithms ^= fuzz_byte(&input) & 31u;
    policy.allowed_mkey_types ^= fuzz_byte(&input) & 15u;
    policy.max_measurements_per_triple = 1u + fuzz_byte(&input) % 2u;
    policy.require_class_id = (fuzz_byte(&input) & 1u) != 0u;
    policy.require_measurement_key = (fuzz_byte(&input) & 1u) != 0u;
    fuzz_fill(&input, identifier, sizeof(identifier));
    fuzz_fill(&input, digest_bytes, sizeof(digest_bytes));
    fuzz_fill(&input, text, sizeof(text));

    enum tcg_concise_evidence_status status = tcg_concise_evidence_validate(&document);
    enum composite_eat_profile_evidence_status policy_status =
        composite_eat_profile_validate_local_evidence(&document, &policy, &policy_length);
    if (status != TCG_CONCISE_EVIDENCE_OK) {
        fuzz_check(tcg_concise_evidence_get_size(&document, &required) != TCG_CONCISE_EVIDENCE_OK);
        fuzz_check(policy_status != COMPOSITE_EAT_PROFILE_EVIDENCE_OK);
        return 0;
    }
    fuzz_check(tcg_concise_evidence_get_size(&document, &required) == TCG_CONCISE_EVIDENCE_OK);
    fuzz_check(required > 0u && required <= sizeof(encoded));
    fuzz_check(tcg_concise_evidence_encode(&document, encoded, sizeof(encoded), &encoded_length) ==
               TCG_CONCISE_EVIDENCE_OK);
    fuzz_check(encoded_length == required);
    struct fuzz_output output = {streamed, sizeof(streamed), 0u, 0u, SIZE_MAX};
    fuzz_check(tcg_concise_evidence_encode_write(&document, fuzz_write, &output, sizeof(streamed),
                                                 &encoded_length) == TCG_CONCISE_EVIDENCE_OK);
    fuzz_check(output.length == required && encoded_length == required);
    fuzz_check(memcmp(encoded, streamed, required) == 0);
    output.length = 0u;
    output.calls = 0u;
    fuzz_check(tcg_concise_evidence_encode_write(&document, fuzz_write, &output, required - 1u,
                                                 &encoded_length) ==
               TCG_CONCISE_EVIDENCE_BUFFER_TOO_SMALL);
    fuzz_check(output.calls == 0u);
    output.fail_after = required / 2u;
    fuzz_check(tcg_concise_evidence_encode_write(&document, fuzz_write, &output, sizeof(streamed),
                                                 &encoded_length) ==
               TCG_CONCISE_EVIDENCE_WRITE_ERROR);
    if (policy_status == COMPOSITE_EAT_PROFILE_EVIDENCE_OK) {
        fuzz_check(policy_length == required);
    }
    return 0;
}
