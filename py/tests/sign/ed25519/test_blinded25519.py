# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven tests for blinded Ed25519.

Reads vectors/blinded_ed25519.json, which is a per-file symlink into the
canonical testvectors/ tree at the repo root. The same JSON file is consumed
by the Go side at sign/ed25519/blinded25519_shared_vectors_test.go, so any
divergence between the Go and Python implementations surfaces here as a
failed assertion.

Each vector applies an ordered list of blind factors to a private key and
records the resulting blinded public key and a signature over the message
under the cumulatively blinded private key. A single-factor vector tests one
blinding step; a multi-factor vector tests N successive blindings.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc.sign.ed25519 import SigningKey

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
    # The shared schema records the full 64-byte Ed25519 private key
    # (seed || pubkey); pynacl's SigningKey takes only the 32-byte seed.
    seed = bytes.fromhex(vector["private_key_hex"])[:32]
    message = bytes.fromhex(vector["message_hex"])
    expected_pubkey = bytes.fromhex(vector["blinded_pubkey_hex"])
    expected_signature = bytes.fromhex(vector["blinded_signature_hex"])
    factors = [bytes.fromhex(fh) for fh in vector["blind_factors_hex"]]
    assert factors, "vector must have at least one blind factor"

    key = SigningKey(seed)
    for factor in factors:
        key = key.blind(factor)

    # nacl's sign() returns signature || message; the bare signature is the
    # first 64 bytes.
    signature = key.sign(message)[:64]

    assert bytes(key.verify_key) == expected_pubkey, "blinded pubkey mismatch"
    assert signature == expected_signature, "signature mismatch"
    assert key.verify_key.verify(message, signature) == message, "self-verify failed"
