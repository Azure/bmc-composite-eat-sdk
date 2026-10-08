// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPOSITE_EAT_REFERENCE_POLICY_H_
#define COMPOSITE_EAT_REFERENCE_POLICY_H_

#include <stddef.h>

#include "composite_eat/profile_evidence.h"
#include "composite_eat/types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI                                                    \
    "https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/"

enum composite_eat_reference_policy_status {
    COMPOSITE_EAT_REFERENCE_POLICY_OK = 0,
    COMPOSITE_EAT_REFERENCE_POLICY_BAD_ARGUMENT,
    COMPOSITE_EAT_REFERENCE_POLICY_PROFILE_ERROR,
    COMPOSITE_EAT_REFERENCE_POLICY_CONTENT_FORMAT_ERROR,
    COMPOSITE_EAT_REFERENCE_POLICY_SCHEMA_ERROR,
    COMPOSITE_EAT_REFERENCE_POLICY_PLATFORM_POLICY_ERROR,
    COMPOSITE_EAT_REFERENCE_POLICY_LIMIT_EXCEEDED,
    COMPOSITE_EAT_REFERENCE_POLICY_ENCODING_ERROR,
    COMPOSITE_EAT_REFERENCE_POLICY_SNAPSHOT_MISMATCH,
};

struct composite_eat_reference_evidence {
    const struct tcg_concise_evidence_document *document;
    const struct composite_eat_profile_evidence_policy *policy;
    /* Return zero only when the concrete document is authorized for this platform. */
    void *platform_policy_context;
    int (*platform_policy_validate)(void *context,
                                    const struct tcg_concise_evidence_document *document);
};

/*
 * Validate the SDK reference deployment policy. Each claim-273 value must be
 * caller-owned, immutable, buffered TCG DICE Concise Evidence. The helper
 * validates and deterministically re-encodes every typed document, requiring
 * byte identity with the pinned snapshot before token preparation. The
 * caller-supplied platform policy callback must additionally approve each
 * document's concrete environment and measurement semantics. The callback
 * and its context are borrowed, must remain immutable, and must not mutate the
 * document or any of its borrowed fields during validation.
 *
 * This is not a generic IETF Composite EAT profile validator and does not
 * claim conformance to the separate OCP Composite EAT profile.
 */
enum composite_eat_reference_policy_status composite_eat_reference_policy_validate_snapshot(
    const struct composite_eat_evidence_snapshot *snapshot,
    const struct composite_eat_reference_evidence *reference_evidence,
    size_t reference_evidence_count);

#ifdef __cplusplus
}
#endif

#endif /* COMPOSITE_EAT_REFERENCE_POLICY_H_ */
