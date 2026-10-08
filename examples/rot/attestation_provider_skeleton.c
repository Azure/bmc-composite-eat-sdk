// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <string.h>

#include "platform_attestation.h"

struct example_attestation_context {
    const struct composite_eat_der_certificate *certificates;
    size_t certificate_count;
};

static int begin_identity(void *context, void **identity_handle,
                          struct composite_eat_attestation_identity *identity) {
    struct example_attestation_context *provider = context;

    if ((provider == NULL) || (identity_handle == NULL) || (identity == NULL)) {
        return -1;
    }
    identity->certificates = provider->certificates;
    identity->certificate_count = provider->certificate_count;
    *identity_handle = provider;
    return 0;
}

static int hash_start_sha384(void *context, void **hash_handle) {
    (void)context;
    (void)hash_handle;
    return -1;
}

static int hash_update(void *context, void *hash_handle, const uint8_t *data, size_t length) {
    (void)context;
    (void)hash_handle;
    (void)data;
    (void)length;
    return -1;
}

static int hash_finish(void *context, void *hash_handle,
                       uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH]) {
    (void)context;
    (void)hash_handle;
    (void)digest;
    return -1;
}

static void hash_abort(void *context, void *hash_handle) {
    (void)context;
    (void)hash_handle;
}

static int sign_es384_digest(void *context, void *identity_handle,
                             const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                             uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
    (void)context;
    (void)identity_handle;
    (void)digest;
    (void)signature;
    return -1;
}

static int
verify_es384_digest_signature(void *context, void *identity_handle,
                              const uint8_t digest[COMPOSITE_EAT_SHA384_LENGTH],
                              const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH]) {
    (void)context;
    (void)identity_handle;
    (void)digest;
    (void)signature;
    return -1;
}

static void end_identity(void *context, void *identity_handle) {
    (void)context;
    (void)identity_handle;
}

const struct example_attestation_provider example_attestation_provider = {
    .context = NULL,
    .begin_identity = begin_identity,
    .hash_start_sha384 = hash_start_sha384,
    .hash_update = hash_update,
    .hash_finish = hash_finish,
    .hash_abort = hash_abort,
    .sign_es384_digest = sign_es384_digest,
    .verify_es384_digest_signature = verify_es384_digest_signature,
    .end_identity = end_identity,
};
