# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven tests for plain Ed25519 verification.

Reads vectors/ed25519.json, which is a per-file symlink into the canonical
testvectors/ tree at the repo root. The same JSON file is consumed by the
Go side at sign/ed25519/plain_vectors_test.go, so any divergence between
the Go and Python implementations surfaces here as a failed assertion.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc.sign.ed25519 import Ed25519Scheme

VECTORS_PATH = Path(__file__).parent / "vectors" / "ed25519.json"


def _load_vectors() -> list[dict]:
    with VECTORS_PATH.open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1
    assert doc["primitive"] == "ed25519"
    return doc["vectors"]


@pytest.mark.parametrize(
    "vector",
    _load_vectors(),
    ids=lambda v: v["name"],
)
def test_plain_ed25519_vector(vector: dict) -> None:
    public_key = bytes.fromhex(vector["public_key_hex"])
    message = bytes.fromhex(vector["message_hex"])
    signature = bytes.fromhex(vector["signature_hex"])

    assert Ed25519Scheme.verify(public_key, message, signature), \
        "verify must succeed on recorded vector"

    bad = bytearray(signature)
    bad[0] ^= 0xff
    assert not Ed25519Scheme.verify(public_key, message, bytes(bad)), \
        "verify must fail after flipping signature[0]"
