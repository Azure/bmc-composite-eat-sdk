# TCG DICE Concise Evidence Helper

## Scope

The optional `bmc::tcg_concise_evidence` target serializes the bounded TCG DICE
Concise Evidence subset selected by this reference implementation. It is not an
authoritative evidence profile and does not define platform measurement
semantics.

Platform adapters own measurement collection, coherent snapshots, environment
identifiers, measured-element keys, algorithms, and appraisal policy. The main
token builder continues to treat claim `273` evidence as opaque registered-
format bytes or a deterministic byte stream.

## Content Format

`COMPOSITE_EAT_TCG_CONCISE_EVIDENCE_CONTENT_FORMAT` is `10571`, the IANA CoAP
Content-Format for `application/ce+cbor`. An adapter using the reference
deployment's TCG representation places that value beside the encoded Concise
Evidence body.
The token core does not force this Content-Format because another Composite EAT
profile may select a different registered evidence representation.

The CoAP Content-Format for `application/eat-ucs+cbor` is 267. It is not the
Lead evidence format selected by the reference deployment.

## Validation Layers

`tcg_concise_evidence_validate` checks only the implemented structural subset:
identifier shapes, required pointers, digest lengths, supported fields, and
nonempty triples and measurements.

`composite_eat_profile_validate_local_evidence` applies caller-supplied policy:
allowed measured-element and algorithm forms, required environment fields,
field lengths, counts, duplicate measured-element keys, flags, names, and total
encoded length.

The helper supports multiple evidence triples, multiple digests per
measurement, SHA-256, SHA-384, SHA-512, integer and text algorithm identifiers,
unsigned/text/UUID/OID measured-element keys, selected flags, and optional
measurement names. Unsupported TCG triples and extensions are rejected rather
than accepted as opaque CBOR.

`composite_eat_reference_policy_validate_snapshot` adds the closed reference
deployment contract. It requires the exact profile URI from
`COMPOSITE_EAT_IETF_DRAFT_00_PROFILE_URI`, at least one buffered 10571 entry,
validates every corresponding typed document, requires a caller-supplied
platform callback to approve its concrete environment and measurement
semantics, re-encodes each document, and requires byte identity with the pinned
claim-273 bytes. It does not validate a generic IETF profile or establish OCP
profile conformance.

## Serialization

Call `tcg_concise_evidence_get_size` before writing, or call
`tcg_concise_evidence_encode` with an insufficient or NULL buffer to retrieve
the required length. `tcg_concise_evidence_encode_write` streams deterministic,
definite-length CBOR through a caller callback and never truncates silently.

The document and every borrowed view remain immutable for the complete size and
write operation. A platform using a streamed claim-273 entry supplies the exact
encoded length to `struct composite_eat_local_evidence` and emits the same bytes
on every signing and finish pass.

The fail-closed RoT reference example deliberately uses buffered evidence.
Streaming remains available to generic token-builder integrations, but a
separately named integration policy must prove replay coherence before using it.

## Schema Validation

Conformance tests use TCG `dice-coev` at
`3e1b724f1154add5d5289df90ad8b2e0e9d5532a`. The resolved `coev.cddl` SHA-256 is
`9306b3dc490687e87f41c2f3b942f940ca24577e233ad6b4e3ec53120446ae6f`.

The standalone export does not embed its imported CoRIM definitions. Assemble
the complete map-root schema with the matching CoRIM source before validating
generated CBOR. Tests must pin and verify every schema input and the assembled
schema hash; they must not fetch moving network content during validation. The
schema assembled on 2026-09-08 with `cddlc` 0.4.5 and
`--start=concise-evidence` has SHA-256
`5b3f619be21a200953fadddfbd3bd91f5fb04bbba85ea54d20184e6e7a47b16e`.
The optional test suite validates the helper's standalone bytes and the exact
claim-273 bytes extracted from both a newly signed reference token and the
checked-in interoperability vector against this pinned schema. The validation
script also requires RubyGems launchers for exactly `cddlc` 0.4.5 and `cddl`
0.12.14 and invokes those pinned versions explicitly. It pins their executable
payload SHA-256 values to
`e42735597f2a73582706e42c53e484884176b90152d54f0e95d230c9008667c8` and
`1f377b0fd8b8b161a28b6a9683e854875c9de76f7673699be19c2aa868d094e4`,
respectively.