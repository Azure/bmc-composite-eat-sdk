#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from verify import verify  # noqa: E402


def expect_rejected(token: bytes, anchor: bytes) -> None:
    try:
        verify(token, anchor)
    except (InvalidSignature, ValueError):
        return
    raise AssertionError("invalid token was accepted")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("token", type=Path)
    parser.add_argument("trust_anchor", type=Path)
    args = parser.parse_args()

    token = args.token.read_bytes()
    anchor = args.trust_anchor.read_bytes()
    verify(token, anchor)
    expect_rejected(token + b"\x00", anchor)
    expect_rejected(token[:-1] + bytes([token[-1] ^ 1]), anchor)
    expect_rejected(token, anchor[:-1] + bytes([anchor[-1] ^ 1]))


if __name__ == "__main__":
    main()
