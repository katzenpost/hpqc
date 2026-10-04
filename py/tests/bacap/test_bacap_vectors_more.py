# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven tests for the layout, tombstone, position and negative files.

The Go side reads the same files in bacap/bacap_vectors_more_test.go.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from hpqc.bacap import (
    BACAPError,
    BoxIDMismatch,
    CannotRewind,
    DecryptionFailed,
    IndexNotInChannel,
    InvalidArgument,
    MessageBoxIndex,
    ReadCap,
    SignatureVerificationFailed,
    StatefulReader,
    WriteCap,
)

VECTORS_DIR = Path(__file__).parent / "vectors"


def _load(name: str, primitive: str) -> list[dict]:
    with (VECTORS_DIR / name).open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1, f"unexpected format_version in {name}"
    assert doc["primitive"] == primitive
    assert doc["vectors"], f"{name}: empty vectors array"
    return doc["vectors"]


def _advanced(idx: MessageBoxIndex, n: int) -> MessageBoxIndex:
    return idx.advance_index_to(idx.idx_64 + n) if n else idx


@pytest.mark.parametrize("vector", _load("layout.json", "bacap_layout"), ids=lambda v: v["name"])
def test_layout(vector: dict) -> None:
    wc_bytes = bytes.fromhex(vector["writecap_hex"])
    wc = WriteCap.from_bytes(wc_bytes)
    assert wc.to_bytes() == wc_bytes, "WriteCap does not round-trip"

    rc = wc.read_cap()
    assert bytes(rc.root_public_key) == bytes.fromhex(vector["expected_root_public_key_hex"])
    assert rc.to_bytes() == bytes.fromhex(vector["expected_readcap_hex"]), "derived ReadCap"
    assert ReadCap.from_bytes(rc.to_bytes()).to_bytes() == rc.to_bytes(), "ReadCap does not round-trip"

    idx = wc.message_box_index
    assert idx.to_bytes() == bytes.fromhex(vector["expected_index_hex"])
    assert idx.idx_64 == vector["expected_idx64"]


@pytest.mark.parametrize("vector", _load("tombstone.json", "bacap_tombstone"), ids=lambda v: v["name"])
def test_tombstone(vector: dict) -> None:
    wc = WriteCap.from_bytes(bytes.fromhex(vector["writecap_hex"]))
    idx = _advanced(wc.message_box_index, vector["advance_by"])
    ctx = bytes.fromhex(vector["ctx_hex"])

    box, sig = idx.sign_box(wc, ctx, b"")
    assert box == bytes.fromhex(vector["expected_box_id_hex"])
    assert sig == bytes.fromhex(vector["expected_signature_hex"])
    assert idx.decrypt_for_context(box, ctx, b"", sig) == b""


@pytest.mark.parametrize("vector", _load("position.json", "bacap_position"), ids=lambda v: v["name"])
def test_position(vector: dict) -> None:
    rc = ReadCap.from_bytes(bytes.fromhex(vector["readcap_hex"]))
    idx = MessageBoxIndex.from_bytes(bytes.fromhex(vector["index_hex"]))
    if vector["reachable"]:
        rc.contains(idx)
        assert rc.position_at(idx).index.to_bytes() == idx.to_bytes()
    else:
        with pytest.raises(IndexNotInChannel):
            rc.contains(idx)
        with pytest.raises(IndexNotInChannel):
            rc.position_at(idx)


# What each category must raise in this port.
_CATEGORY = {
    "cannot_rewind": CannotRewind,
    "index_exhausted": InvalidArgument,
    "signature_invalid": SignatureVerificationFailed,
    "decrypt_failed": DecryptionFailed,
    "box_mismatch": BoxIDMismatch,
    "malformed": InvalidArgument,
}


@pytest.mark.parametrize("vector", _load("negative.json", "bacap_negative"), ids=lambda v: v["name"])
def test_negative(vector: dict) -> None:
    op = vector["operation"]
    expected = _CATEGORY[vector["category"]]

    def cap_index() -> tuple[WriteCap, MessageBoxIndex]:
        wc = WriteCap.from_bytes(bytes.fromhex(vector["writecap_hex"]))
        return wc, _advanced(wc.message_box_index, vector["advance_by"])

    box = bytes.fromhex(vector.get("box_id_hex", ""))
    ct = bytes.fromhex(vector.get("ciphertext_hex", ""))
    sig = bytes.fromhex(vector.get("signature_hex", ""))
    ctx = bytes.fromhex(vector.get("ctx_hex", ""))
    blob = bytes.fromhex(vector.get("blob_hex", ""))

    if op == "verify_box":
        assert MessageBoxIndex.verify_box(box, ct, sig) is False
        return

    if op == "open":
        wc, idx = cap_index()
        with pytest.raises(expected):
            idx.open_for_context(wc.read_cap(), ctx, box, ct, sig)
        with pytest.raises(expected):
            wc.read_cap().position_at(idx).open(ctx, box, ct, sig)

    with pytest.raises(expected):
        if op == "advance_index_to":
            MessageBoxIndex.from_bytes(bytes.fromhex(vector["index_hex"])).advance_index_to(vector["advance_to"])
        elif op == "next_index":
            MessageBoxIndex.from_bytes(bytes.fromhex(vector["index_hex"])).next_index()
        elif op == "decrypt":
            _, idx = cap_index()
            idx.decrypt_for_context(box, ctx, ct, sig)
        elif op == "open":
            wc, idx = cap_index()
            assert idx.box_id_for_context(wc.read_cap(), ctx) != box
            StatefulReader(wc.read_cap(), ctx, next_index=idx).decrypt_next(ctx, box, ct, sig)
        elif op == "parse_message_box_index":
            MessageBoxIndex.from_bytes(blob)
        elif op == "parse_read_cap":
            ReadCap.from_bytes(blob)
        elif op == "parse_write_cap":
            WriteCap.from_bytes(blob)
        else:
            pytest.fail(f"unknown operation {op!r}")


def test_categories_are_bacap_errors() -> None:
    for exc in _CATEGORY.values():
        assert issubclass(exc, BACAPError)
