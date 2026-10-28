# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-language sealed box vector tests.

Reads vectors/sealedbox.json (a per-file symlink into the canonical
testvectors/protocols/ tree). Each Go-produced box must open to the
recorded plaintext, and sealing again from the generator's
deterministic HKDF streams must reproduce the recorded keys and
ciphertext byte for byte.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

import pytest

from hpqc.bacap.stateless import _hkdf_blake2b
from hpqc.nike.ctidh1024 import CTIDH1024
from hpqc.nike.hybrid import HybridNIKE
from hpqc.nike.scheme import Scheme as NIKEScheme
from hpqc.nike.x25519 import X25519
from hpqc.protocols.sealedbox import SealedBoxScheme

VECTORS_PATH = Path(__file__).parent / "vectors" / "sealedbox.json"

_SCHEMES: dict[str, Callable[[], NIKEScheme]] = {
    "x25519": X25519,
    "X25519-CTIDH1024": lambda: HybridNIKE(X25519(), CTIDH1024(), name="X25519-CTIDH1024"),
}


def _load_vectors() -> list[dict]:
    with VECTORS_PATH.open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1
    assert doc["primitive"] == "nike_sealed_box"
    return doc["vectors"]


def _deterministic_reader(label: str, vector_name: str) -> Callable[[int], bytes]:
    """The generator's deterministicReader: an HKDF-BLAKE2b-512 stream."""
    stream = _hkdf_blake2b(b"hpqc-vector-seed-" + label.encode(), b"", vector_name.encode(), 255 * 64)
    pos = 0

    def read(n: int) -> bytes:
        nonlocal pos
        out = stream[pos : pos + n]
        assert len(out) == n, "deterministic stream exhausted"
        pos += n
        return out

    return read


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["name"])
def test_open(vector: dict) -> None:
    nike = _SCHEMES[vector["nike_name"]]()
    s = SealedBoxScheme(nike)
    priv = nike.private_key_from_bytes(bytes.fromhex(vector["recipient_private_key_hex"]))
    pub = nike.public_key_from_bytes(bytes.fromhex(vector["recipient_public_key_hex"]))
    assert nike.derive_public_key(priv) == pub

    got = s.open(priv, pub, bytes.fromhex(vector["ciphertext_hex"]))
    assert got == bytes.fromhex(vector["plaintext_hex"])


@pytest.mark.parametrize("vector", _load_vectors(), ids=lambda v: v["name"])
def test_seal_reproduces(vector: dict) -> None:
    nike = _SCHEMES[vector["nike_name"]]()
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair_from_entropy(
        _deterministic_reader("sealedbox-recipient", vector["name"])
    )
    assert pub.to_bytes().hex() == vector["recipient_public_key_hex"]
    assert priv.to_bytes().hex() == vector["recipient_private_key_hex"]

    ct = s.seal_with_entropy(
        pub,
        bytes.fromhex(vector["plaintext_hex"]),
        _deterministic_reader("sealedbox-ephemeral", vector["name"]),
    )
    assert ct.hex() == vector["ciphertext_hex"]
