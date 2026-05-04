# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven tests for blinded Ed25519.

Reads vectors/blinded_ed25519.json, which is a per-file symlink into the
canonical testvectors/ tree at the repo root. The same JSON file is consumed
by the Go side at sign/ed25519/blinded25519_shared_vectors_test.go, so any
divergence between Go and Python surfaces here as a failed assertion.

The Python implementation referenced below does not yet exist; this file
will fail to collect until py/hpqc/sign/ed25519/blinded25519.py lands as
part of the BACAP port. That is the intended state on this branch.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

VECTORS_PATH = Path(__file__).parent / "vectors" / "blinded_ed25519.json"


def _load_vectors() -> list[dict]:
    with VECTORS_PATH.open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1
    assert doc["primitive"] == "blinded_ed25519"
    return doc["vectors"]


@pytest.mark.parametrize(
    "vector",
    _load_vectors(),
    ids=lambda v: v["name"],
)
def test_blinded_ed25519_vector(vector: dict) -> None:
    from hpqc.sign.ed25519.blinded25519 import PrivateKey

    priv = PrivateKey.from_bytes(bytes.fromhex(vector["private_key_hex"]))
    factor = bytes.fromhex(vector["blind_factor_hex"])
    message = bytes.fromhex(vector["message_hex"])

    blinded = priv.blind(factor)
    blinded_pub = blinded.public_key()
    sig = blinded.sign(message)

    assert blinded_pub.to_bytes() == bytes.fromhex(vector["blinded_pubkey_hex"])
    assert sig == bytes.fromhex(vector["signature_hex"])
    assert blinded_pub.verify(message, sig)
