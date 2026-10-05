# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Positions, contains and open_for_context. Mirrors bacap/position_test.go."""
from __future__ import annotations

import dataclasses

import pytest

from hpqc.bacap import (
    MAX_CONTAINS_WALK,
    BACAPError,
    BoxIDMismatch,
    EmptyBox,
    IndexNotInChannel,
    IndexTooFar,
    InvalidArgument,
    ReadCapSize,
    ReadPosition,
    WriteCap,
    WritePosition,
)

CTX = b"pigeonhole context"


def test_positions_round_trip() -> None:
    wc = WriteCap.generate()
    w = wc.start()
    r = wc.read_cap().start()
    for i in range(5):
        msg = bytes([i]) + b"m"
        box, ct, sig = w.encrypt(CTX, msg)
        assert r.box_id(CTX) == box
        assert w.box_id(CTX) == box
        assert r.open(CTX, box, ct, sig) == msg
        w, r = w.next(), r.next()
        assert w.index == r.index


def test_open_rejects_another_box() -> None:
    here = WriteCap.generate().start()
    there = here.next()
    # A tombstone for the next box: its signature verifies and there is
    # nothing to decrypt, so only the box check rejects it here.
    box, sig = there.tombstone(CTX)
    with pytest.raises(BoxIDMismatch):
        here.read_position().open(CTX, box, b"", sig)
    assert there.read_position().open(CTX, box, b"", sig) == b""
    with pytest.raises(EmptyBox):
        here.read_position().open(CTX, bytes(32), b"", sig)


def test_position_at() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()
    start = rc.message_box_index
    ahead = start.advance_index_to(start.idx_64 + 40)
    assert rc.position_at(ahead).index == ahead
    wc.position_at(ahead)

    foreign = dataclasses.replace(WriteCap.generate().message_box_index, idx_64=ahead.idx_64)
    with pytest.raises(IndexNotInChannel):
        rc.position_at(foreign)

    mutated = start.mutate_kdf_state(b"salt").advance_index_to(ahead.idx_64)
    with pytest.raises(IndexNotInChannel):
        rc.position_at(mutated)

    with pytest.raises(IndexNotInChannel):
        rc.with_message_box_index(ahead).position_at(start)

    far = dataclasses.replace(start, idx_64=start.idx_64 + MAX_CONTAINS_WALK + 1)
    with pytest.raises(IndexTooFar):
        rc.position_at(far)


def test_position_bytes() -> None:
    wc = WriteCap.generate()
    w = wc.start().advance_to(wc.message_box_index.idx_64 + 3)
    assert WritePosition.from_bytes(w.to_bytes()).index == w.index
    rb = w.read_position().to_bytes()
    assert ReadPosition.from_bytes(rb).index == w.index

    # An index from another stream, written after the cap, is refused.
    other = WriteCap.generate().message_box_index.to_bytes()
    with pytest.raises(BACAPError):
        ReadPosition.from_bytes(rb[:ReadCapSize] + other)


def test_positions_are_not_constructible() -> None:
    wc = WriteCap.generate()
    with pytest.raises(InvalidArgument):
        ReadPosition(None, wc.read_cap(), wc.message_box_index)
    with pytest.raises(InvalidArgument):
        WritePosition(None, wc, wc.message_box_index)
