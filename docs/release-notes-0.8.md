# 0.8 Release Notes

Version 0.8 is a source-only, non-production reference implementation for BMC
and Root-of-Trust integration. CMake package metadata uses `0.8.0`; the public
API is explicitly marked by `BMC_COMPOSITE_EAT_API_DRAFT`. This version does not
create a stable API, a production support commitment, or a binary release.

Microsoft-owned first-party material is licensed under MIT. Vendored QCBOR
retains its BSD-3-Clause license and upstream notices.

## Standards Status

The SDK aligns with
[draft-sun-rats-composite-eat-00](https://datatracker.ietf.org/doc/html/draft-sun-rats-composite-eat-00),
an active individual Internet-Draft that expires 2027-03-05. It is work in
progress, not an RFC or an IETF-endorsed standard.

The SDK no longer redistributes an IETF draft snapshot. Documentation and the
public-header reference link to the published `-00` text, with current status
available from the Datatracker document page. Profile constants and policy
tests remain unchanged.

The OCP Composite EAT Profile contribution remains under project review. This
SDK does not claim complete OCP profile conformance. Its private BMC-to-RoT
generation request is an SDK integration contract, not an IETF wire protocol.

The optional spdmd adapter is pinned to the unmerged
[NVIDIA/spdm PR #2](https://github.com/NVIDIA/spdm/pull/2) at commit
`5627b8844ab298477ee4d0ab744d24266e7c6b28`. It is a reference integration, not
a released upstream API dependency.

## Implementation and Compatibility

The private generation-request codec requires a 32-byte nonce and between one
and 64 detached-device records. Empty record sets are rejected. These are
constraints of this SDK contract, not requirements imposed on every Composite
EAT deployment.

The public APIs and private wire contract may evolve with the IETF and OCP draft
work before the first stable release. Such changes require release notes and a
version update. `BMC_COMPOSITE_EAT_API_DRAFT` replaces
`BMC_COMPOSITE_EAT_API_EXPERIMENTAL`; the retained
`BMC_COMPOSITE_EAT_VERSION_PRERELEASE` macro is now an empty string. Draft API
status is separate from the numeric project version.

## TCG DICE Concise Evidence

The `bmc::tcg_concise_evidence` target provides bounded structural serialization
and caller-supplied evidence-policy validation. It does not define platform
measurement semantics or require Content-Format 10571 for all Composite EAT
profiles.

The reference RoT integration uses `COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI`
and requires every Lead evidence entry to be buffered, policy-approved TCG DICE
Concise Evidence under `application/ce+cbor` (CoAP Content-Format 10571).
This is an additional reference deployment policy, not a generic IETF
requirement or an OCP conformance claim. Each `composite_eat_reference_evidence`
entry requires a `platform_policy_validate` callback; missing or rejecting
callbacks fail closed.

Optional offline CDDL validation pins TCG `dice-coev` commit
`3e1b724f1154add5d5289df90ad8b2e0e9d5532a`, schema/input hashes, `cddlc` 0.4.5,
and `cddl` 0.12.14. The assembled map-root schema SHA-256 is
`5b3f619be21a200953fadddfbd3bd91f5fb04bbba85ea54d20184e6e7a47b16e`.

## Streaming and Lifetime Contract

- `composite_eat_write_signing_input` writes the exact signing input through a
  caller-owned writer.
- `composite_eat_finish_write` streams the final token;
  `composite_eat_finish` remains the caller-buffer wrapper.
- Generic local evidence can use immutable bytes or a deterministic, replayable
  writer with an exact declared length. Callback and exact-length failures
  return `COMPOSITE_EAT_WRITE_ERROR`.
- The builder workspace does not retain the complete payload.

After `composite_eat_prepare` succeeds, the prepared state borrows the request,
evidence snapshot, evidence sources and writer contexts, identity descriptor,
certificate array, and DER buffers. They must remain immutable and valid through
signing, final output, and `composite_eat_clear`.

The fail-closed reference path uses a buffered snapshot and verifies exact byte
identity against the typed Concise Evidence document before preparation. Generic
streaming callbacks are trusted platform callbacks: they must terminate, obey
platform resource limits, and provide deterministic replay. The synchronous
portable core does not enforce a platform execution timeout.

## Validation and Dependencies

The tests and synthetic-token generator now use always-active checks instead
of runtime assertions. Side-effecting checks execute with `NDEBUG`, and file
writes/closes run before their results are checked. C/C++ single-evaluation and
intentional-failure regressions cover the helper; CI includes Debug, Release,
and RelWithDebInfo builds. The default self-contained suite now has twelve tests.

Earlier local GCC and ASan/UBSan validation covered the ten original SDK tests with
examples enabled, including independent verification of generated and checked-in
synthetic COSE tokens and verifier negative cases. The default C-only build and
installed-package consumer check also pass. The checked-in vector hashes match
their documented manifest. These are host tests, not device validation or proof
of a production firmware integration.

The Python test requirement is `cryptography>=50.0.0,<51`. The verifier tests
pass with 50.0.0, and the resolved dependency audit reported no known advisories
on 2026-09-29. That result is scoped to the tested environment and advisory
database at that time; it is not a vulnerability-free claim. Production C
cryptography remains delegated to platform providers.

CI now uses full action commit pins, read-only default token permissions,
non-persistent checkout credentials, bounded job timeouts, and fail-fast
sanitizers. Workflow lint/security checks, an installed-package test, CodeQL,
dependency review, and Dependabot are configured. Local actionlint/ShellCheck
and offline pedantic zizmor checks pass; hosted CodeQL and dependency-review
execution still requires the repository security services and a GitHub run.

Three opt-in libFuzzer targets cover the request decoder, structured evidence
validation, and builder state transitions. They instrument SDK/QCBOR code with
ASan/UBSan and use checks independent of `NDEBUG`. Seeded CI smoke tests are
configured; longer campaigns require an explicit local budget. An initial
60-second-per-target campaign completed 10,921,865 executions without a
sanitizer or property failure. This bounded result does not establish complete
input or state coverage.

The full release validation and independent review gates remain open, including
final-tree fuzzing, pinned CDDL, and optional spdmd integration/sanitizer checks. No
hardware, complete OCP-conformance, or Microsoft product-support claim is made.

## Responsibilities Outside the SDK

Production key management, cryptographic providers, trusted measurement
selection/storage, authorization, transport, Detached EAT Bundle assembly, and
verifier appraisal remain integration responsibilities. Skeleton providers and
synthetic certificates are examples, not production implementations or trust
anchors.