# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven tests for the Falcon-padded-512-Ed25519 hybrid verifier.

Reads vectors/falcon_padded_512_ed25519.json, a per-file symlink into
the canonical testvectors/ tree at the repo root. The same JSON file is
consumed by the Go side at sign/hybrid/falcon_vectors_test.go; a
divergence in either component scheme's encoding or in the on-wire
concatenation order surfaces here as a failed assertion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc.sign.hybrid import FalconPadded512Ed25519

VECTORS_PATH = (
    Path(__file__).parent / "vectors" / "falcon_padded_512_ed25519.json"
)


def _load_vectors() -> list[dict]:
    with VECTORS_PATH.open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1
    assert doc["primitive"] == "falcon_padded_512_ed25519"
    return doc["vectors"]


@pytest.mark.parametrize(
    "vector",
    _load_vectors(),
    ids=lambda v: v["name"],
)
def test_falcon_padded_512_ed25519_vector(vector: dict) -> None:
    public_key = bytes.fromhex(vector["public_key_hex"])
    message = bytes.fromhex(vector["message_hex"])
    signature = bytes.fromhex(vector["signature_hex"])

    assert len(public_key) == FalconPadded512Ed25519.public_key_size
    assert len(signature) == FalconPadded512Ed25519.signature_size

    assert FalconPadded512Ed25519.verify(public_key, message, signature), \
        "verify must succeed on recorded vector"

    head = bytearray(signature)
    head[0] ^= 0xff
    assert not FalconPadded512Ed25519.verify(public_key, message, bytes(head)), \
        "verify must fail after flipping signature[0] (Falcon half)"

    tail = bytearray(signature)
    tail[-1] ^= 0xff
    assert not FalconPadded512Ed25519.verify(public_key, message, bytes(tail)), \
        "verify must fail after flipping signature[-1] (Ed25519 half)"
