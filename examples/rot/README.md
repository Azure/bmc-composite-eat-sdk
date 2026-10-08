# Root Of Trust Examples

These C examples run inside the Root of Trust firmware boundary:

- `platform_evidence.h` defines a provider for one coherent, already serialized
  evidence snapshot and its typed TCG Concise Evidence policy inputs;
- `platform_attestation.h` defines certificate, SHA-384, and opaque ES384
  operations;
- the provider skeletons show where platform services are connected;
- `software_platform.c` demonstrates the complete split-phase SDK lifecycle;
- the attestation provider keeps platform-specific signing state behind opaque
  identity handles and verifies each signature locally before publication.

The skeleton provider instances have NULL contexts and deliberately fail until
an integrator supplies platform state and implementations. They are compilable
contracts, not production defaults. The evidence adapter must serialize its
native measurements into a registered content format before returning the
snapshot; the generic SDK does not define that evidence schema.

The platform still owns command authorization, request serialization,
transport framing, concurrency, reset handling, evidence serialization, key
storage, and transient-state cleanup. The reference lifecycle rejects any
profile other than `COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI`, any Lead evidence
format other than 10571, and any claim-273 bytes that differ from the
policy-approved typed Concise Evidence document.
