# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven cross-language tests for the BACAP Python port.

Reads the vectors/{message_box_index,box_id,encrypt}.json files (each a
per-file symlink into the canonical testvectors/bacap/ tree) and asserts
that the Python implementation reproduces the byte-for-byte expected
outputs recorded by the Go primitives in the generator.

Each consumer here covers the same surface as bacap/bacap_vectors_test.go
on the Go side, so a divergence between the two ports surfaces here as a
mismatch on whichever side runs first.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc.bacap import MessageBoxIndex, ReadCap, WriteCap
from hpqc.sign.ed25519 import VerifyKey

VECTORS_DIR = Path(__file__).parent / "vectors"


def _load(name: str, primitive: str) -> list[dict]:
    with (VECTORS_DIR / name).open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1, f"unexpected format_version in {name}"
    assert doc["primitive"] == primitive, (
        f"{name}: expected primitive {primitive!r}, got {doc['primitive']!r}"
    )
    assert doc["vectors"], f"{name}: empty vectors array"
    return doc["vectors"]


# ----- MessageBoxIndex.advance_index_to -----


@pytest.mark.parametrize(
    "vector",
    _load("message_box_index.json", "bacap_message_box_index"),
    ids=lambda v: v["name"],
)
def test_message_box_index_advance(vector: dict) -> None:
    initial = MessageBoxIndex.from_bytes(bytes.fromhex(vector["initial_index_hex"]))
    advanced = initial.advance_index_to(vector["advance_to"])
    assert advanced.to_bytes() == bytes.fromhex(vector["expected_index_hex"])


# ----- box-ID derivation -----


@pytest.mark.parametrize(
    "vector",
    _load("box_id.json", "bacap_box_id"),
    ids=lambda v: v["name"],
)
def test_box_id(vector: dict) -> None:
    wc_bytes = bytes.fromhex(vector["writecap_hex"])
    wc = WriteCap.from_bytes(wc_bytes)
    rc = wc.read_cap()
    idx = wc.first_message_box_index
    advance_by = vector["advance_by"]
    if advance_by:
        idx = idx.advance_index_to(idx.idx_64 + advance_by)
    ctx = bytes.fromhex(vector["ctx_hex"])
    expected = bytes.fromhex(vector["expected_box_id_hex"])

    if vector["use_context"]:
        got = idx.box_id_for_context(rc, ctx)
    else:
        # DeriveMessageBoxID needs the root pubkey; recover it from the
        # WriteCap blob (bytes [32:64]) so this test does not assume a
        # particular accessor on the WriteCap class.
        root_pub = VerifyKey(wc_bytes[32:64])
        got = idx.derive_message_box_id(root_pub)

    assert got == expected, "box ID mismatch"


# ----- mutate_kdf_state -----


@pytest.mark.parametrize(
    "vector",
    _load("mutate_kdf_state.json", "bacap_mutate_kdf_state"),
    ids=lambda v: v["name"],
)
def test_mutate_kdf_state(vector: dict) -> None:
    wc = WriteCap.from_bytes(bytes.fromhex(vector["writecap_hex"]))
    rc = wc.read_cap()
    idx = wc.first_message_box_index
    advance_by = vector["advance_by"]
    if advance_by:
        idx = idx.advance_index_to(idx.idx_64 + advance_by)

    mutated = idx.mutate_kdf_state(bytes.fromhex(vector["salt_hex"]))
    assert mutated.to_bytes() == bytes.fromhex(
        vector["expected_mutated_index_hex"]
    ), "mutated index mismatch"

    box_id = mutated.box_id_for_context(rc, bytes.fromhex(vector["read_ctx_hex"]))
    assert box_id == bytes.fromhex(
        vector["expected_mutated_box_id_hex"]
    ), "mutated box ID mismatch"


# ----- encrypt_for_context -----


@pytest.mark.parametrize(
    "vector",
    _load("encrypt.json", "bacap_encrypt"),
    ids=lambda v: v["name"],
)
def test_encrypt_for_context(vector: dict) -> None:
    wc = WriteCap.from_bytes(bytes.fromhex(vector["writecap_hex"]))
    idx = wc.first_message_box_index
    advance_by = vector["advance_by"]
    if advance_by:
        idx = idx.advance_index_to(idx.idx_64 + advance_by)
    ctx = bytes.fromhex(vector["ctx_hex"])
    plaintext = bytes.fromhex(vector["plaintext_hex"])

    box_id, ciphertext, sig = idx.encrypt_for_context(wc, ctx, plaintext)

    assert box_id == bytes.fromhex(vector["expected_box_id_hex"]), "box ID mismatch"
    assert ciphertext == bytes.fromhex(vector["expected_ciphertext_hex"]), "ciphertext mismatch"
    assert sig == bytes.fromhex(vector["expected_signature_hex"]), "signature mismatch"

    # Round-trip decrypt as a sanity check.
    recovered = idx.decrypt_for_context(box_id, ctx, ciphertext, sig)
    assert recovered == plaintext, "decrypt round-trip mismatch"
