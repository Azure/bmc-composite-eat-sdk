# Synthetic Interoperability Vector

These files contain a synthetic two-certificate P-384 attestation identity and
a Composite EAT main token. They are test data only and are not production
credentials or trust anchors.

| File | SHA-256 |
|---|---|
| `synthetic-token.cbor` | `f2c77da897a9efc64748ea57d65ca749c1ac9bd004c3f8f4036f0ceb3fd0e66b` |
| `synthetic-anchor.der` | `32db88a9045d777f96ba43ac2a747ad1d5a463d1a13bc0e535a76725b707b026` |

Verify the vector with:

```bash
python3 tools/verify.py \
  tests/vectors/synthetic-token.cbor \
  tests/vectors/synthetic-anchor.der
```

The token contains one detached-submodule digest under `env.device.0`, the
exact published IETF `-00` profile URI, and one policy-approved TCG DICE
Concise Evidence entry under CoAP Content-Format 10571.
`generate_test_token` creates a semantically equivalent token and chain for
each test run. ECDSA signatures, keys, certificate serializations, and validity
times may differ, so regenerated files are not expected to be byte-identical to
this fixed vector.
