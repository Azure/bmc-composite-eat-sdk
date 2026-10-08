// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPOSITE_EAT_PROFILE_EVIDENCE_H_
#define COMPOSITE_EAT_PROFILE_EVIDENCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "composite_eat/tcg_concise_evidence.h"

#define COMPOSITE_EAT_PROFILE_MKEY_UINT (1u << 0)
#define COMPOSITE_EAT_PROFILE_MKEY_TEXT (1u << 1)
#define COMPOSITE_EAT_PROFILE_MKEY_UUID (1u << 2)
#define COMPOSITE_EAT_PROFILE_MKEY_OID (1u << 3)

#define COMPOSITE_EAT_PROFILE_ALGORITHM_SHA256 (1u << 0)
#define COMPOSITE_EAT_PROFILE_ALGORITHM_SHA384 (1u << 1)
#define COMPOSITE_EAT_PROFILE_ALGORITHM_SHA512 (1u << 2)
#define COMPOSITE_EAT_PROFILE_ALGORITHM_INTEGER (1u << 3)
#define COMPOSITE_EAT_PROFILE_ALGORITHM_TEXT (1u << 4)

enum composite_eat_profile_evidence_status {
    COMPOSITE_EAT_PROFILE_EVIDENCE_OK = 0,
    COMPOSITE_EAT_PROFILE_EVIDENCE_BAD_ARGUMENT,
    COMPOSITE_EAT_PROFILE_EVIDENCE_SCHEMA_ERROR,
    COMPOSITE_EAT_PROFILE_EVIDENCE_POLICY_ERROR,
    COMPOSITE_EAT_PROFILE_EVIDENCE_LIMIT_EXCEEDED,
};

struct composite_eat_profile_evidence_policy {
    size_t max_triples;
    size_t max_measurements_per_triple;
    size_t max_digests_per_measurement;
    size_t max_identifier_length;
    size_t max_text_length;
    size_t max_encoded_length;
    uint32_t allowed_mkey_types;
    uint32_t allowed_algorithms;
    bool require_measurement_key;
    bool require_class;
    bool require_class_id;
    bool require_vendor;
    bool require_model;
    bool allow_flags;
    bool allow_name;
};

enum composite_eat_profile_evidence_status composite_eat_profile_validate_environment(
    const struct tcg_concise_evidence_environment *environment,
    const struct composite_eat_profile_evidence_policy *policy);

enum composite_eat_profile_evidence_status composite_eat_profile_validate_local_evidence(
    const struct tcg_concise_evidence_document *document,
    const struct composite_eat_profile_evidence_policy *policy, size_t *encoded_length);

#endif /* COMPOSITE_EAT_PROFILE_EVIDENCE_H_ */
