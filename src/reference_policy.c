// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <string.h>

#include "composite_eat/reference_policy.h"

struct reference_compare_writer {
    const uint8_t *expected;
    size_t expected_length;
    size_t offset;
};

static int reference_compare_write(void *context, const uint8_t *data, size_t length) {
    struct reference_compare_writer *writer = context;

    if ((writer == NULL) || ((data == NULL) && (length != 0u)) ||
        (writer->offset > writer->expected_length) ||
        ((writer->expected_length - writer->offset) < length) ||
        (memcmp(&writer->expected[writer->offset], data, length) != 0)) {
        return -1;
    }
    writer->offset += length;
    return 0;
}

static enum composite_eat_reference_policy_status
reference_map_profile_status(enum composite_eat_profile_evidence_status status) {
    switch (status) {
    case COMPOSITE_EAT_PROFILE_EVIDENCE_OK:
        return COMPOSITE_EAT_REFERENCE_POLICY_OK;
    case COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR:
        return COMPOSITE_EAT_REFERENCE_POLICY_SCHEMA_ERROR;
    case COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR:
        return COMPOSITE_EAT_REFERENCE_POLICY_PLATFORM_POLICY_ERROR;
    case COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED:
        return COMPOSITE_EAT_REFERENCE_POLICY_LIMIT_EXCEEDED;
    case COMPOSITE_EAT_PROFILE_EVIDENCE_BAD_ARGUMENT:
    default:
        return COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT;
    }
}

enum composite_eat_reference_policy_status composite_eat_reference_policy_validate_snapshot(
    const struct composite_eat_evidence_snapshot *snapshot,
    const struct composite_eat_reference_evidence *reference_evidence,
    size_t reference_evidence_count) {
    static const uint8_t profile[] = COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI;
    size_t index;

    if ((snapshot == NULL) || (reference_evidence == NULL) || (reference_evidence_count == 0u) ||
        (snapshot->local_evidence == NULL) ||
        (snapshot->local_evidence_count != reference_evidence_count)) {
        return COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT;
    }
    if ((snapshot->profile.data == NULL) || (snapshot->profile.length != (sizeof(profile) - 1u)) ||
        (memcmp(snapshot->profile.data, profile, sizeof(profile) - 1u) != 0)) {
        return COMPOSITE_EAT_REFERENCE_POLICY_PROFILE_ERROR;
    }
    if (composite_eat_validate_evidence_snapshot(snapshot) != COMPOSITE_EAT_OK) {
        return COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT;
    }

    for (index = 0u; index < reference_evidence_count; ++index) {
        const struct composite_eat_local_evidence *local = &snapshot->local_evidence[index];
        const struct composite_eat_reference_evidence *reference = &reference_evidence[index];
        struct reference_compare_writer writer;
        enum composite_eat_profile_evidence_status profile_status;
        enum tcg_concise_evidence_status encode_status;
        size_t encoded_length = 0u;

        if (local->content_format != COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT) {
            return COMPOSITE_EAT_REFERENCE_POLICY_CONTENT_FORMAT_ERROR;
        }
        if ((local->encoded.data == NULL) || (local->encoded.length == 0u) ||
            (local->write != NULL) || (local->encoded_length != 0u) ||
            (reference->document == NULL) || (reference->policy == NULL) ||
            (reference->platform_policy_validate == NULL)) {
            return COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT;
        }

        profile_status = composite_eat_profile_validate_local_evidence(
            reference->document, reference->policy, &encoded_length);
        if (profile_status != COMPOSITE_EAT_PROFILE_EVIDENCE_OK) {
            return reference_map_profile_status(profile_status);
        }
        if (reference->platform_policy_validate(reference->platform_policy_context,
                                                reference->document) != 0) {
            return COMPOSITE_EAT_REFERENCE_POLICY_PLATFORM_POLICY_ERROR;
        }
        if (encoded_length != local->encoded.length) {
            return COMPOSITE_EAT_REFERENCE_POLICY_SNAPSHOT_MISMATCH;
        }

        writer = (struct reference_compare_writer){
            .expected = local->encoded.data,
            .expected_length = local->encoded.length,
        };
        encode_status =
            tcg_concise_evidence_encode_write(reference->document, reference_compare_write, &writer,
                                              local->encoded.length, &encoded_length);
        if (encode_status == TCG_CONCISE_EVIDENCE_WRITE_ERROR) {
            return COMPOSITE_EAT_REFERENCE_POLICY_SNAPSHOT_MISMATCH;
        }
        if (encode_status != TCG_CONCISE_EVIDENCE_OK) {
            return COMPOSITE_EAT_REFERENCE_POLICY_ENCODING_ERROR;
        }
        if ((encoded_length != local->encoded.length) || (writer.offset != local->encoded.length)) {
            return COMPOSITE_EAT_REFERENCE_POLICY_SNAPSHOT_MISMATCH;
        }
    }

    return COMPOSITE_EAT_REFERENCE_POLICY_OK;
}
