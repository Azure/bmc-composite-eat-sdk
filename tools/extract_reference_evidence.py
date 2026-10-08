#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import io
from pathlib import Path

import cbor2

REFERENCE_PROFILE = "https://datatracker.ietf.org/doc/draft-sun-rats-composite-eat/"
TCG_CONCISE_EVIDENCE_CONTENT_FORMAT = 10571


def decode_exact(data: bytes) -> object:
    stream = io.BytesIO(data)
    value = cbor2.CBORDecoder(stream).decode()
    if stream.read(1) != b"":
        raise ValueError("trailing token data")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("token", type=Path)
    parser.add_argument("evidence", type=Path)
    args = parser.parse_args()

    token = decode_exact(args.token.read_bytes())
    if not isinstance(token, cbor2.CBORTag) or token.tag != 61:
        raise ValueError("missing CWT tag")
    cose = token.value
    if not isinstance(cose, cbor2.CBORTag) or cose.tag != 18:
        raise ValueError("missing COSE_Sign1 tag")
    if not isinstance(cose.value, list) or len(cose.value) != 4:
        raise ValueError("invalid COSE_Sign1")
    claims = decode_exact(cose.value[2])
    if not isinstance(claims, dict) or claims.get(265) != REFERENCE_PROFILE:
        raise ValueError("invalid reference profile")
    measurements = claims.get(273)
    if not isinstance(measurements, list) or len(measurements) != 1:
        raise ValueError("expected one Lead evidence entry")
    entry = measurements[0]
    if (
        not isinstance(entry, list)
        or len(entry) != 2
        or entry[0] != TCG_CONCISE_EVIDENCE_CONTENT_FORMAT
        or not isinstance(entry[1], bytes)
    ):
        raise ValueError("invalid Lead evidence entry")
    args.evidence.write_bytes(entry[1])


if __name__ == "__main__":
    main()