# RoT Evidence And Claim Ownership

## Evidence Sources

| Source | Token location |
|---|---|
| Root of Trust firmware and security state | Claim `273` |
| BMC state measured or authenticated by the Root of Trust | Claim `273` |
| Peripheral evidence collected by the BMC | Detached digest entries in claim `266` |

Claim `273` must represent protected local evidence. Arbitrary measurements
received from BMC software are not local evidence. If the Root of Trust did not
measure a value directly, it must authenticate the source and commit the result
to its protected snapshot before representing it as local evidence.

## Provider Boundary

The platform evidence provider retrieves measurements from its native source,
such as measurement registers, a measured-boot log, or authenticated manifest.
For this reference deployment it constructs a typed TCG DICE Concise Evidence
document, applies caller-supplied platform policy, and pins the encoded bytes
before returning:

```c
struct composite_eat_local_evidence {
  uint16_t content_format; /* 10571 for the reference deployment */
    struct composite_eat_buffer encoded;
};
```

The token builder treats `encoded` as opaque and emits:

```cbor-diag
273: [
  [content-format, h'encoded-local-evidence']
]
```

`composite_eat_reference_policy_validate_snapshot` re-encodes the typed
document and requires byte identity with this buffered snapshot before
`composite_eat_prepare`. There is no malformed-10571 fallback to generic CBOR.
The evidence provider implementation, source identifiers, and storage layout
remain outside the token builder.

## Top-Level Ownership

```cbor-diag
{
  10: h'verifier-nonce',
  256: h'rot-ueid',
  265: "https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/",
  266: {
    "env.device.0": [-43, h'48-byte-detached-claims-digest']
  },
  273: [
    [10571, h'TCG-DICE-Concise-Evidence']
  ]
}
```

- The Verifier originates claim `10`; the BMC relays it.
- The BMC supplies detached digest records for claim `266`.
- The Root of Trust owns claims `256`, `265`, and `273`.
- The token builder owns deterministic claim encoding.

This is the published IETF Composite EAT `-00` profile with an additional
reference deployment constraint on Lead evidence. It is not an assertion of
OCP Composite EAT profile conformance.

This Composite EAT profile requires at least one detached Claims-Set. If no
peripheral evidence source succeeds, the BMC collector does not request a main
token and returns no Detached EAT Bundle.
