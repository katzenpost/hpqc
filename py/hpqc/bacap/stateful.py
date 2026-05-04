# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Stateful BACAP wrappers built on the stateless layer.

StatefulReader and StatefulWriter carry a mutable next-index pointer
and advance it after each successful read or write. They sit on the
stateless API in stateless.py; everything they do is expressible as a
sequence of stateless calls. Pick whichever shape suits your caller.
"""
from __future__ import annotations

from typing import Optional, Tuple

from .stateless import (
    BoxIDSize,
    MessageBoxIndex,
    ReadCap,
    SignatureSize,
    WriteCap,
)


class StatefulReader:
    """Sequential reader over a BACAP ReadCap.

    Holds the next-index pointer and the conversation context, advancing
    the pointer after each successful decrypt_next.
    """

    def __init__(
        self,
        read_cap: ReadCap,
        ctx: bytes,
        next_index: Optional[MessageBoxIndex] = None,
    ) -> None:
        if read_cap is None:
            raise ValueError("read_cap is None")
        if ctx is None:
            raise ValueError("ctx is None")
        self.read_cap: ReadCap = read_cap
        # Defensive copy of ctx so callers cannot mutate it under us.
        self.ctx: bytes = bytes(ctx)
        if next_index is None:
            # Start at the conversation's first message box.
            self.last_inbox_read: Optional[MessageBoxIndex] = read_cap.first_message_box_index
            self.next_index: Optional[MessageBoxIndex] = read_cap.first_message_box_index
        else:
            # Resuming from a known checkpoint or starting fresh from a
            # specific index; this instance has no prior-read history.
            self.last_inbox_read = None
            self.next_index = next_index

    def next_box_id(self) -> bytes:
        """Returns the box ID this reader will read next, without advancing."""
        if self.next_index is not None:
            cur = self.next_index
        else:
            if self.last_inbox_read is None:
                raise ValueError("both next_index and last_inbox_read are None")
            cur = self.last_inbox_read.next_index()
        return cur.box_id_for_context(self.read_cap, self.ctx)

    def get_current_message_index(self) -> Optional[MessageBoxIndex]:
        """Returns the MessageBoxIndex that will be used for the next read."""
        return self.next_index

    def get_next_message_index(self) -> MessageBoxIndex:
        """Returns what next_index will be after a successful decrypt_next.

        Does NOT advance state; useful for crash-consistency planning.
        """
        if self.next_index is None:
            raise ValueError("next index is None")
        return self.next_index.next_index()

    def decrypt_next(
        self,
        ctx: bytes,
        box: bytes,
        ciphertext: bytes,
        signature: bytes,
    ) -> bytes:
        """Verifies, decrypts, and advances state on success.

        ``ctx`` is the decryption context (passed through to the stateless
        primitive); ``self.ctx`` is the box-ID context. They are the same
        in normal use but the API allows them to differ, mirroring Go.
        """
        if len(box) != BoxIDSize:
            raise ValueError("invalid box length")
        if all(b == 0 for b in box):
            raise ValueError("empty box, no message received")
        if self.next_index is None:
            raise ValueError("next index is None, cannot parse reply")
        if len(signature) != SignatureSize:
            raise ValueError("invalid signature length")

        expected = self.next_index.box_id_for_context(self.read_cap, self.ctx)
        if box != expected:
            raise ValueError("reply does not match expected box ID")

        # Do everything that can fail BEFORE mutating state.
        plaintext = self.next_index.decrypt_for_context(box, ctx, ciphertext, signature)
        next_idx = self.next_index.next_index()

        self.last_inbox_read = self.next_index
        self.next_index = next_idx
        return plaintext


class StatefulWriter:
    """Sequential writer over a BACAP WriteCap.

    Splits the per-message work into prepare_next (encrypt without
    advancing) and advance_state (advance after the courier acks); the
    convenience method encrypt_next does both.
    """

    def __init__(
        self,
        owner: WriteCap,
        ctx: bytes,
        next_index: Optional[MessageBoxIndex] = None,
    ) -> None:
        if ctx is None:
            raise ValueError("ctx is None")
        if next_index is not None and owner is None:
            raise ValueError("owner is None")
        self.write_cap: WriteCap = owner
        self.ctx: bytes = bytes(ctx)
        if next_index is None:
            self.last_outbox_idx: Optional[MessageBoxIndex] = None
            self.next_index: Optional[MessageBoxIndex] = owner.first_message_box_index if owner is not None else None
        else:
            self.last_outbox_idx = None
            self.next_index = next_index

    def next_box_id(self) -> bytes:
        """Returns the box ID this writer will write next, without advancing."""
        if self.next_index is None:
            raise ValueError("next index is None")
        if self.write_cap is None:
            raise ValueError("write_cap is None")
        return self.next_index.box_id_for_context(self.write_cap.read_cap(), self.ctx)

    def get_current_message_index(self) -> Optional[MessageBoxIndex]:
        return self.next_index

    def get_next_message_index(self) -> MessageBoxIndex:
        """Returns what next_index will be after advance_state. No mutation."""
        if self.next_index is None:
            raise ValueError("next index is None")
        return self.next_index.next_index()

    def prepare_next(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypts a message WITHOUT advancing state.

        Returns (box_id, ciphertext, signature). Call advance_state after
        the courier acknowledges receipt.
        """
        if self.next_index is None:
            raise ValueError("next index is None")
        return self.next_index.encrypt_for_context(self.write_cap, self.ctx, plaintext)

    def advance_state(self) -> None:
        """Advances the writer's state to the next index.

        Should only be called after the courier acknowledges receipt.
        """
        if self.next_index is None:
            raise ValueError("next index is None")
        next_idx = self.next_index.next_index()
        self.last_outbox_idx = self.next_index
        self.next_index = next_idx

    def encrypt_next(self, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypts a message and advances state after the encrypt succeeds.

        Equivalent to prepare_next + advance_state; provided for the
        common case where you do not need to defer the advance.
        """
        result = self.prepare_next(plaintext)
        self.advance_state()
        return result
