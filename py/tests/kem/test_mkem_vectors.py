# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-language MKEM vector tests.

Reads vectors/mkem.json (a per-file symlink into the canonical
testvectors/kem/ tree) and confirms that the Python MKEM port
decapsulates Go-produced ciphertexts to the recorded plaintext.

A passing test means the Python and Go sides agree on every layer
in the MKEM stack:

  - the CBOR field naming and canonical encoding of the
    IntermediaryCiphertext shape,
  - ChaCha20-Poly1305 framing (12-byte nonce, 16-byte tag, no AAD),
  - BLAKE2b-256 of the NIKE shared secret as the AEAD key,
  - the underlying CTIDH1024-X25519 hybrid NIKE shared secret bytes.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc.kem.mkem import MKEMScheme
from hpqc.nike.ctidh1024 import CTIDH1024
from hpqc.nike.hybrid import HybridNIKE
from hpqc.nike.x25519 import X25519

VECTORS_PATH = Path(__file__).parent / "vectors" / "mkem.json"


def _load_vectors() -> list[dict]:
    with VECTORS_PATH.open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1
    assert doc["primitive"] == "kem_mkem"
    return doc["vectors"]


@pytest.mark.parametrize(
    "vector",
    _load_vectors(),
    ids=lambda v: v["name"],
)
def test_mkem_decapsulate(vector: dict) -> None:
    # The Python side hardcodes the NIKE; the vector's nike_name field
    # is asserted as a sanity check so a future vector under a
    # different NIKE produces a clear failure.
    nike = HybridNIKE(CTIDH1024(), X25519(), name="CTIDH1024-X25519")
    assert vector["nike_name"] == "CTIDH1024-X25519", (
        f"expected CTIDH1024-X25519 vector, got {vector['nike_name']!r}"
    )
    scheme = MKEMScheme(nike)

    ct_bytes = bytes.fromhex(vector["ciphertext_hex"])
    expected = bytes.fromhex(vector["plaintext_hex"])

    ct = scheme.ciphertext_from_bytes(ct_bytes)
    assert len(ct.dek_ciphertexts) == len(vector["recipient_private_keys_hex"])

    for i, priv_hex in enumerate(vector["recipient_private_keys_hex"]):
        priv = nike.private_key_from_bytes(bytes.fromhex(priv_hex))
        recovered = scheme.decapsulate(priv, ct)
        assert recovered == expected, (
            f"recipient {i}: plaintext mismatch "
            f"(got {recovered!r}, expected {expected!r})"
        )
