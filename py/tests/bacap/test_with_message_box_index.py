# SPDX-FileCopyrightText: © 2026 Katzenpost dev team
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for WriteCap/ReadCap.with_message_box_index (re-basing a cap)."""
from __future__ import annotations

import pytest

from hpqc.bacap import (
    InvalidArgument,
    StatefulReader,
    StatefulWriter,
    WriteCap,
)

CTX = b"hpqc-bacap-with-index-test"


def test_with_message_box_index_rebases_and_preserves_source() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()

    orig = rc.message_box_index
    target = rc.message_box_index.advance_index_to(rc.message_box_index.idx_64 + 3)

    rc2 = rc.with_message_box_index(target)
    wc2 = wc.with_message_box_index(target)

    # The re-based caps point at target...
    assert rc2.message_box_index == target
    assert wc2.message_box_index == target
    # ...the sources are unchanged...
    assert rc.message_box_index == orig
    assert wc.message_box_index == orig
    assert rc.message_box_index.idx_64 != target.idx_64

    # A reader and writer built from the re-based caps meet at target.
    reader = StatefulReader(rc2, CTX)
    writer = StatefulWriter(wc2, CTX)
    msg = b"written at the re-based position"
    box_id, ct, sig = writer.encrypt_next(msg)
    assert reader.decrypt_next(CTX, box_id, ct, sig) == msg


def test_with_message_box_index_nil_rejected() -> None:
    wc = WriteCap.generate()
    with pytest.raises(InvalidArgument):
        wc.with_message_box_index(None)
    with pytest.raises(InvalidArgument):
        wc.read_cap().with_message_box_index(None)
