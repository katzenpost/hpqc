# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven tests for Falcon-padded-512 verification.

Reads vectors/falcon_padded_512.json, a per-file symlink into the
canonical testvectors/ tree at the repo root. The same JSON file is
consumed by the Go side at sign/falcon/falcon_vectors_test.go; a
divergence between Go's PQClean-via-cgo encoding and the Python port's
PQClean-via-pqcrypto verifier surfaces here as a failed assertion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc.sign.falcon import FalconPadded512Scheme

VECTORS_PATH = Path(__file__).parent / "vectors" / "falcon_padded_512.json"


def _load_vectors() -> list[dict]:
    with VECTORS_PATH.open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1
    assert doc["primitive"] == "falcon_padded_512"
    return doc["vectors"]


@pytest.mark.parametrize(
    "vector",
    _load_vectors(),
    ids=lambda v: v["name"],
)
def test_falcon_padded_512_vector(vector: dict) -> None:
    public_key = bytes.fromhex(vector["public_key_hex"])
    message = bytes.fromhex(vector["message_hex"])
    signature = bytes.fromhex(vector["signature_hex"])

    assert len(public_key) == FalconPadded512Scheme.public_key_size
    assert len(signature) == FalconPadded512Scheme.signature_size
    assert FalconPadded512Scheme.verify(public_key, message, signature), \
        "verify must succeed on recorded vector"

    bad = bytearray(signature)
    bad[0] ^= 0xff
    assert not FalconPadded512Scheme.verify(public_key, message, bytes(bad)), \
        "verify must fail after flipping signature[0]"
