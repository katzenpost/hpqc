# SPDX-License-Identifier: AGPL-3.0-only
"""An empty box is signed, never encrypted, so no AEAD bounds the floor.

A tombstone is an empty box and every retention sweep writes one, so this
is the path the declared cryptography floor rests on. Were a tombstone
ever routed through ``encrypt_for_context`` instead, the floor would rise
to the version whose ``AESGCMSIV`` accepts zero-length data.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hpqc.bacap import WriteCap
from hpqc.bacap.exceptions import InvalidArgument
from hpqc.bacap.stateless import _CRYPTOGRAPHY, _EMPTY_AEAD_FROM

CTX = b"hpqc-empty-box-floor"

VECTORS = Path(__file__).parent / "vectors"


def test_an_empty_box_signs_and_opens() -> None:
    cap = WriteCap.generate(os.urandom)
    idx = cap.message_box_index
    box_id, sig = idx.sign_box(cap, CTX, b"")
    assert idx.decrypt_for_context(box_id, CTX, b"", sig) == b""


def test_an_empty_box_verifies_against_its_box_id() -> None:
    cap = WriteCap.generate(os.urandom)
    idx = cap.message_box_index
    box_id, sig = idx.sign_box(cap, CTX, b"")
    assert idx.verify_box(box_id, b"", sig)


def test_a_tombstone_takes_the_box_a_message_would_have() -> None:
    cap = WriteCap.generate(os.urandom)
    idx = cap.message_box_index
    message_box, _, _ = idx.encrypt_for_context(cap, CTX, b"hi")
    tombstone_box, _ = idx.sign_box(cap, CTX, b"")
    assert tombstone_box == message_box


def test_encrypting_an_empty_plaintext_follows_the_declared_floor() -> None:
    """Below cryptography 45 it is refused by name, not by the AEAD's own
    ValueError; from 45 it works. Either way the caller knows which."""
    cap = WriteCap.generate(os.urandom)
    idx = cap.message_box_index
    if _CRYPTOGRAPHY < _EMPTY_AEAD_FROM:
        with pytest.raises(InvalidArgument, match="sign_box"):
            idx.encrypt_for_context(cap, CTX, b"")
        return
    box_id, ciphertext, sig = idx.encrypt_for_context(cap, CTX, b"")
    assert idx.decrypt_for_context(box_id, CTX, ciphertext, sig) == b""


def test_reading_an_encrypted_empty_plaintext_follows_the_floor() -> None:
    """The Go side does encrypt empty plaintexts, and its vector's box
    verifies on every version. Below cryptography 45 the AEAD cannot open
    the tag-only ciphertext, so this says the version is too old rather
    than reporting a good box as tampered with."""
    rows = json.loads(
        (VECTORS / "encrypt.json").read_text(encoding="utf-8")
    )["vectors"]
    name = "cap_random_start_encrypt_empty_plaintext"
    vector = [row for row in rows if row["name"] == name][0]
    cap = WriteCap.from_bytes(bytes.fromhex(vector["writecap_hex"]))
    idx = cap.message_box_index
    if vector["advance_by"]:
        idx = idx.advance_index_to(idx.idx_64 + vector["advance_by"])
    ctx = bytes.fromhex(vector["ctx_hex"])
    box = bytes.fromhex(vector["expected_box_id_hex"])
    ciphertext = bytes.fromhex(vector["expected_ciphertext_hex"])
    signature = bytes.fromhex(vector["expected_signature_hex"])

    assert len(ciphertext) == 16
    assert idx.verify_box(box, ciphertext, signature)

    if _CRYPTOGRAPHY < _EMPTY_AEAD_FROM:
        with pytest.raises(InvalidArgument, match="45 or newer"):
            idx.decrypt_for_context(box, ctx, ciphertext, signature)
        return
    assert idx.decrypt_for_context(box, ctx, ciphertext, signature) == b""
