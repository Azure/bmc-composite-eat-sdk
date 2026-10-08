# RoT Attestation Identity And COSE Headers

## Identity Invariant

One RoT attestation identity is used for each token:

- a non-exportable P-384 attestation private key signs the token;
- `x5chain[0]` is its leaf/end-entity certificate in canonical DER;
- the leaf Subject Public Key Info contains the corresponding public key;
- protected `x5t` is SHA-384 over the exact `x5chain[0]` DER bytes;
- the ES384 signature verifies with that leaf public key.

## Retrieval And Signing

1. Pin the authorized attestation identity for one operation.
2. Retrieve leaf-first canonical DER certificate views.
3. Compute the SHA-384 leaf thumbprint.
4. Pass certificate views and thumbprint to `composite_eat_prepare`.
5. Hash every Sig_structure part returned by
  `composite_eat_write_signing_input`.
6. Invoke the platform attestation signer with the pinned identity and digest.
7. Verify the raw 96-byte `r || s` signature with `x5chain[0]` over that exact
  Sig_structure digest.
8. Pass the verified signature to `composite_eat_finish`.
9. Clear the token-builder operation state with `composite_eat_clear`.
10. Release the pinned identity on every completion path.

No private key or opaque platform key handle enters the token builder.

The token builder does not parse DER or validate certificate path semantics.
The platform adapter must reject malformed certificates, incorrect ordering,
key/leaf mismatch, missing issuers, and certificates not authorized for the
selected attestation profile before calling `composite_eat_prepare`.

`tools/verify.py` is an interoperability test verifier, not a production PKIX
validator or appraisal engine.

## COSE Headers

Protected headers:

```cbor-diag
{
  1: -35,
  3: "application/eat+cwt",
  34: [-43, h'SHA-384(DER-leaf-certificate)']
}
```

Unprotected headers:

```cbor-diag
{
  33: [
    h'DER-leaf-certificate',
    h'DER-issuer-certificate',
    h'DER-root-certificate'
  ]
}
```

A single self-signed certificate may be represented directly as a byte string.
For a chain, certificates are ordered leaf first and issuer-by-issuer. The
Verifier validates to an independently configured trust anchor; certificates
carried in the token are untrusted input.
