#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import hashlib
import io
import re
from datetime import datetime, timezone
from pathlib import Path

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

REFERENCE_PROFILE = "https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/"
TCG_CONCISE_EVIDENCE_CONTENT_FORMAT = 10571


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_chain(value: object) -> list[bytes]:
    if isinstance(value, bytes):
        return [value]
    require(isinstance(value, list) and len(value) >= 2, "invalid x5chain")
    require(all(isinstance(item, bytes) and item for item in value), "invalid certificate")
    return value


def decode_exact(data: bytes, description: str) -> object:
    stream = io.BytesIO(data)
    decoded = cbor2.CBORDecoder(stream).decode()
    require(stream.read(1) == b"", f"trailing data in {description}")
    return decoded


def verify(token_bytes: bytes, trust_anchor_bytes: bytes) -> None:
    outer = decode_exact(token_bytes, "token")
    require(isinstance(outer, cbor2.CBORTag) and outer.tag == 61, "missing CWT tag 61")
    cose = outer.value
    require(
        isinstance(cose, cbor2.CBORTag) and cose.tag == 18,
        "missing COSE_Sign1 tag 18",
    )
    require(isinstance(cose.value, list) and len(cose.value) == 4, "invalid COSE_Sign1")

    protected_bytes, unprotected, payload_bytes, signature = cose.value
    require(isinstance(protected_bytes, bytes), "protected headers are not bytes")
    require(isinstance(unprotected, dict), "unprotected headers are not a map")
    require(isinstance(payload_bytes, bytes), "payload is not bytes")
    require(
        isinstance(signature, bytes) and len(signature) == 96,
        "invalid ES384 signature length",
    )

    protected = decode_exact(protected_bytes, "protected headers")
    require(
        isinstance(protected, dict) and set(protected) == {1, 3, 34},
        "unexpected protected headers",
    )
    require(protected.get(1) == -35, "protected algorithm is not ES384")
    require(protected.get(3) == "application/eat+cwt", "invalid content type")
    thumbprint = protected.get(34)
    require(isinstance(thumbprint, list) and len(thumbprint) == 2, "invalid x5t")
    require(
        thumbprint[0] == -43
        and isinstance(thumbprint[1], bytes)
        and len(thumbprint[1]) == 48,
        "invalid x5t algorithm or digest",
    )

    require(set(unprotected) == {33}, "unexpected unprotected headers")
    chain = parse_chain(unprotected.get(33))
    require(
        hashlib.sha384(chain[0]).digest() == thumbprint[1],
        "x5t does not match the leaf certificate",
    )
    require(chain[-1] == trust_anchor_bytes, "chain does not end at the trust anchor")

    certificates = [x509.load_der_x509_certificate(item) for item in chain]
    now = datetime.now(timezone.utc)
    for certificate in certificates:
        require(certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc,
                "certificate is not currently valid")
    for child, issuer in zip(certificates, certificates[1:]):
        issuer_key = issuer.public_key()
        require(isinstance(issuer_key, ec.EllipticCurvePublicKey), "issuer key is not elliptic curve")
        issuer_key.verify(
            child.signature,
            child.tbs_certificate_bytes,
            ec.ECDSA(child.signature_hash_algorithm),
        )

    root = certificates[-1]
    root_key = root.public_key()
    require(isinstance(root_key, ec.EllipticCurvePublicKey), "root key is not elliptic curve")
    root_key.verify(root.signature, root.tbs_certificate_bytes, ec.ECDSA(root.signature_hash_algorithm))
    require(root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
            "trust anchor is not a CA")
    require(root.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign,
            "trust anchor cannot sign certificates")

    leaf = certificates[0]
    require(not leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
            "leaf certificate is a CA")
    require(leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature,
            "leaf certificate cannot sign")
    public_key = leaf.public_key()
    require(
        isinstance(public_key, ec.EllipticCurvePublicKey)
        and isinstance(public_key.curve, ec.SECP384R1),
        "leaf key is not P-384",
    )

    signed = cbor2.dumps(["Signature1", protected_bytes, b"", payload_bytes], canonical=True)
    r = int.from_bytes(signature[:48], "big")
    s = int.from_bytes(signature[48:], "big")
    public_key.verify(encode_dss_signature(r, s), signed, ec.ECDSA(hashes.SHA384()))

    claims = decode_exact(payload_bytes, "claims set")
    require(isinstance(claims, dict), "claims set is not a map")
    require({10, 256, 265, 266, 273}.issubset(claims), "missing required claims")
    require(
        isinstance(claims.get(10), bytes) and len(claims[10]) == 32,
        "invalid nonce claim",
    )
    require(isinstance(claims.get(256), bytes) and 7 <= len(claims[256]) <= 33, "invalid UEID")
    require(claims.get(265) == REFERENCE_PROFILE, "invalid reference profile")
    require(isinstance(claims.get(266), dict), "missing submodules")
    require(isinstance(claims.get(273), list) and claims[273], "missing measurements")

    for environment, detached_digest in claims[266].items():
        require(
            isinstance(environment, str)
            and re.fullmatch(r"env(?:\.[a-z0-9-]+)+", environment) is not None,
            "invalid environment identifier",
        )
        require(
            isinstance(detached_digest, list)
            and len(detached_digest) == 2
            and detached_digest[0] == -43
            and isinstance(detached_digest[1], bytes)
            and len(detached_digest[1]) == 48,
            "invalid detached digest",
        )
    for measurement in claims[273]:
        require(
            isinstance(measurement, list)
            and len(measurement) == 2
            and measurement[0] == TCG_CONCISE_EVIDENCE_CONTENT_FORMAT
            and isinstance(measurement[1], bytes),
            "invalid local evidence entry",
        )
        concise_evidence = decode_exact(measurement[1], "TCG Concise Evidence")
        require(
            isinstance(concise_evidence, dict)
            and set(concise_evidence) == {0}
            and isinstance(concise_evidence[0], dict)
            and set(concise_evidence[0]) == {0}
            and isinstance(concise_evidence[0][0], list)
            and concise_evidence[0][0],
            "invalid TCG Concise Evidence root",
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a Composite EAT main token")
    parser.add_argument("token", type=Path)
    parser.add_argument("trust_anchor", type=Path)
    args = parser.parse_args()

    verify(args.token.read_bytes(), args.trust_anchor.read_bytes())
    print("Composite EAT verification passed")


if __name__ == "__main__":
    main()
