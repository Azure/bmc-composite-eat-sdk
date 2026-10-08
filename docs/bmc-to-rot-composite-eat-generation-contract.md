# BMC-to-RoT Composite EAT Generation Contract

## Scope

This private integration contract defines how a BMC collector asks a platform
Root of Trust to generate the signed Composite EAT main token. It is used by
this reference implementation and is not an IETF protocol or API.

The published
[Composite EAT Internet-Draft -00](https://datatracker.ietf.org/doc/html/draft-sun-rats-composite-eat-00)
is the draft reference for main-token claims, CWT/COSE structure, Detached EAT
Bundle semantics, and verification guidance. It is work in progress, not an RFC
or IETF endorsement; see the
[Datatracker document page](https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/)
for current status. This contract only defines the BMC-to-RoT request,
successful response boundary, and ownership of transport metadata.

Contract version 1 carries a Verifier nonce and detached Sub-Attester digests
from the BMC collector. A platform may use a different transport or framing,
but both sides must preserve the typed semantics defined here.

## Generation Request

```cddl
composite-eat-generation-request = {
  1: 1,
  2: bstr .size 32,
  3: [+ device-record]
}

device-record = {
  1: tstr .size (1..64),
  2: [-43, bstr .size 48]
}
```

Map labels are:

| Label | Meaning |
|---:|---|
| `1` | Contract version, exactly `1` |
| `2` | Verifier nonce |
| `3` | One through 64 detached-device records |

Each environment identifier must be unique, begin with `env.`, contain only
lowercase ASCII letters, digits, hyphens, and nonempty dot-separated
components, and fit within 64 bytes. Every detached digest uses COSE algorithm
`-43` and contains exactly 48 bytes.

## Strict Processing

The receiver rejects:

- missing, repeated, or unknown map labels;
- indefinite-length maps, arrays, strings, or byte strings;
- unsupported versions or digest algorithms;
- duplicate environment identifiers;
- invalid `env.*` syntax, uppercase/non-ASCII input, or embedded NUL;
- out-of-range nonce, identifier, record-count, or digest lengths;
- CBOR tags and trailing bytes.

The transport may fragment this message, but it must deliver the exact
reassembled byte sequence to the generation-request decoder. The maximum
encoded message size is `COMPOSITE_EAT_MAX_GENERATION_REQUEST_LENGTH` bytes.

The SDK encoder emits deterministic, definite-length CBOR. The decoder enforces
the strict schema and rejects indefinite containers, but callers should not use
the request bytes as a cryptographic canonicalization boundary.

## Successful Response

The successful response body is the complete signed Composite EAT main token:

```text
CWT tag 61 containing COSE_Sign1 tag 18
```

The RoT returns those token bytes unchanged. It does not return the tag-602
Detached EAT Bundle; spdmd assembles that bundle from the main token and the
detached Claims-Sets it retained during collection.

The SDK does not define a second response structure because the response body
is already defined by the Internet-Draft. `composite_eat_finish` constructs the
main-token bytes, and `COMPOSITE_EAT_MAX_RESPONSE_LENGTH` bounds their size.

## Transport Status And Errors

Command identifiers, completion status, required response length, framing,
fragmentation, request correlation, timeout, retry, and reset behavior belong
to the platform transport. They are not fields in the generation request or
the signed token.

The transport must distinguish at least:

- successful completion with nonempty main-token bytes;
- an invalid or unsupported request;
- busy or unauthorized operation;
- insufficient response capacity with the complete required length;
- internal generation or signing failure; and
- timeout, reset, or unavailable RoT service.

No failure returns a partial signed token.
