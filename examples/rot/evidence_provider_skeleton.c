// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include "platform_evidence.h"

struct example_evidence_context {
    const struct composite_eat_evidence_snapshot *evidence;
    /* Each entry must include the platform's semantic authorization callback. */
    const struct composite_eat_reference_evidence *reference_evidence;
    size_t reference_evidence_count;
};

static int begin_snapshot(void *context, void **snapshot_handle,
                          struct composite_eat_evidence_snapshot *evidence,
                          const struct composite_eat_reference_evidence **reference_evidence,
                          size_t *reference_evidence_count) {
    const struct example_evidence_context *provider = context;

    if ((provider == NULL) || (provider->evidence == NULL) || (snapshot_handle == NULL) ||
        (evidence == NULL) || (reference_evidence == NULL) || (reference_evidence_count == NULL)) {
        return -1;
    }
    *snapshot_handle = context;
    *evidence = *provider->evidence;
    *reference_evidence = provider->reference_evidence;
    *reference_evidence_count = provider->reference_evidence_count;
    return 0;
}

static void end_snapshot(void *context, void *snapshot_handle) {
    (void)context;
    (void)snapshot_handle;
}

const struct example_evidence_provider example_evidence_provider = {
    .context = NULL,
    .begin_snapshot = begin_snapshot,
    .end_snapshot = end_snapshot,
};
