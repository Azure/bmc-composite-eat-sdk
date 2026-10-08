// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef COMPOSITE_EAT_TOKEN_BUILDER_H
#define COMPOSITE_EAT_TOKEN_BUILDER_H

#include <stddef.h>
#include <stdint.h>

#include "composite_eat/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Draft API implementing the Composite EAT main-token profile documented in
 * https://datatracker.ietf.org/doc/html/draft-sun-rats-composite-eat-00.
 * A workspace/prepared pair represents one operation and is not thread-safe.
 * Use a separate pair for each concurrent operation.
 *
 * A successful prepare copies protected headers into the workspace and borrows
 * the request, evidence, identity, certificate, encoded-evidence, and stream-
 * context objects. Every borrowed object must remain immutable and valid until
 * signing, finish, and clear complete. The private key and opaque key handle
 * never enter this API.
 * Input objects and their borrowed buffers must not overlap workspace or
 * prepared. Every call with non-NULL workspace and prepared pointers clears
 * both objects before validating other arguments, so failure cannot preserve
 * stale operation state.
 *
 * The caller must supply authenticated, profile-authorized local evidence and
 * canonical DER certificates in leaf-first issuer order. The core performs
 * bounded structural validation but does not parse X.509, validate a
 * certificate path, authenticate evidence provenance, or confirm that the
 * supplied thumbprint matches the first certificate. Platform integration
 * must enforce those invariants before prepare.
 *
 * Individual field limits do not guarantee that every maximum-sized input can
 * be combined. prepare returns COMPOSITE_EAT_ENCODING_ERROR if the aggregate
 * claims cannot fit COMPOSITE_EAT_PAYLOAD_MAX.
 *
 * Returns OK, BAD_ARGUMENT, or ENCODING_ERROR. On OK, prepared is ready for
 * write_signing_input. Every failure leaves workspace and prepared cleared.
 */
enum composite_eat_status
composite_eat_prepare(const struct composite_eat_generation_request *request,
                      const struct composite_eat_evidence_snapshot *evidence,
                      const struct composite_eat_attestation_identity *identity,
                      const uint8_t leaf_thumbprint_sha384[COMPOSITE_EAT_SHA384_LENGTH],
                      struct composite_eat_workspace *workspace,
                      struct composite_eat_prepared *prepared);

/*
 * Stream the complete COSE Sig_structure through write. The callback receives
 * deterministic nonempty segments in order and must consume them before
 * returning. Returns OK, BAD_ARGUMENT, STATE_ERROR, or WRITE_ERROR.
 */
enum composite_eat_status composite_eat_write_signing_input(struct composite_eat_prepared *prepared,
                                                            composite_eat_write write,
                                                            void *context);

/*
 * Stream the final token after signing input has completed. The required
 * response length is reported before output begins. A too-small capacity does
 * not invoke write. Returns OK, BAD_ARGUMENT, STATE_ERROR, BUFFER_TOO_SMALL,
 * ENCODING_ERROR, or WRITE_ERROR.
 *
 * A callback failure can occur after earlier segments were accepted. Platforms
 * requiring atomic publication must stream into unpublished storage and expose
 * it only after this function returns OK.
 */
enum composite_eat_status
composite_eat_finish_write(const struct composite_eat_prepared *prepared,
                           const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH],
                           composite_eat_write write, void *context, size_t response_capacity,
                           size_t *response_length);

/*
 * Assemble CWT tag 61 containing COSE_Sign1 tag 18 after signing input is
 * exhausted. signature is raw, fixed-width ES384 r || s. Call with
 * response=NULL and response_capacity=0 to query the required length.
 * COMPOSITE_EAT_BUFFER_TOO_SMALL leaves response untouched and reports the
 * required capacity. A successful call may be repeated with the same prepared
 * state and signature. response must not overlap prepared, workspace,
 * signature, response_length, the identity descriptor, or any certificate
 * buffer. finish structurally revalidates the borrowed identity as a defensive
 * check; the caller must still keep it unchanged after prepare. Other failures
 * set a non-NULL *response_length to zero.
 * This is a caller-buffer wrapper around composite_eat_finish_write. Returns
 * OK, BAD_ARGUMENT, STATE_ERROR, BUFFER_TOO_SMALL, ENCODING_ERROR, or
 * WRITE_ERROR.
 */
enum composite_eat_status
composite_eat_finish(const struct composite_eat_prepared *prepared,
                     const uint8_t signature[COMPOSITE_EAT_ES384_SIGNATURE_LENGTH],
                     uint8_t *response, size_t response_capacity, size_t *response_length);

/*
 * Overwrite caller-owned operation state after success or failure. Both
 * pointers may be NULL and otherwise must refer to distinct objects. Cleared
 * objects may be reused by a later prepare call.
 */
void composite_eat_clear(struct composite_eat_workspace *workspace,
                         struct composite_eat_prepared *prepared);

#ifdef __cplusplus
}
#endif

#endif
