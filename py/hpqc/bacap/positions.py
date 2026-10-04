# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Positions: a capability together with one box on its stream.

The Python counterpart of Go's bacap.ReadPosition and bacap.WritePosition.
Get one from ReadCap.start / WriteCap.start or position_at, then move it with
next / advance_to. A position never pairs a capability with an index from
another stream.
"""
from __future__ import annotations

from typing import Tuple

from .exceptions import InvalidArgument
from .stateless import (
    MessageBoxIndex,
    MessageBoxIndexSize,
    ReadCap,
    ReadCapSize,
    WriteCap,
    WriteCapSize,
)

_TOKEN = object()


class ReadPosition:
    """A read cap and one box on its stream."""

    __slots__ = ("_cap", "_index")

    def __init__(self, token: object, cap: ReadCap, index: MessageBoxIndex) -> None:
        if token is not _TOKEN:
            raise InvalidArgument("use ReadCap.start or ReadCap.position_at")
        self._cap = cap
        self._index = index

    @classmethod
    def _make(cls, cap: ReadCap, index: MessageBoxIndex) -> "ReadPosition":
        return cls(_TOKEN, cap, index)

    @property
    def cap(self) -> ReadCap:
        return self._cap

    @property
    def index(self) -> MessageBoxIndex:
        return self._index

    def next(self) -> "ReadPosition":
        return ReadPosition._make(self._cap, self._index.next_index())

    def advance_to(self, n: int) -> "ReadPosition":
        return ReadPosition._make(self._cap, self._index.advance_index_to(n))

    def box_id(self, ctx: bytes) -> bytes:
        return self._index.box_id_for_context(self._cap, ctx)

    def open(self, ctx: bytes, box: bytes, ciphertext: bytes, signature: bytes) -> bytes:
        """Verifies and decrypts the box at this position. See
        MessageBoxIndex.open_for_context."""
        return self._index.open_for_context(self._cap, ctx, box, ciphertext, signature)

    def to_bytes(self) -> bytes:
        """The read cap's bytes followed by the index's."""
        return self._cap.to_bytes() + self._index.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> "ReadPosition":
        """Decodes a position, checking its index is on its cap's stream."""
        if len(data) != ReadCapSize + MessageBoxIndexSize:
            raise InvalidArgument("invalid ReadPosition binary size")
        cap = ReadCap.from_bytes(data[:ReadCapSize])
        return cap.position_at(MessageBoxIndex.from_bytes(data[ReadCapSize:]))


class WritePosition:
    """A write cap and one box on its stream."""

    __slots__ = ("_cap", "_index")

    def __init__(self, token: object, cap: WriteCap, index: MessageBoxIndex) -> None:
        if token is not _TOKEN:
            raise InvalidArgument("use WriteCap.start or WriteCap.position_at")
        self._cap = cap
        self._index = index

    @classmethod
    def _make(cls, cap: WriteCap, index: MessageBoxIndex) -> "WritePosition":
        return cls(_TOKEN, cap, index)

    @property
    def cap(self) -> WriteCap:
        return self._cap

    @property
    def index(self) -> MessageBoxIndex:
        return self._index

    def next(self) -> "WritePosition":
        return WritePosition._make(self._cap, self._index.next_index())

    def advance_to(self, n: int) -> "WritePosition":
        return WritePosition._make(self._cap, self._index.advance_index_to(n))

    def box_id(self, ctx: bytes) -> bytes:
        return self._index.box_id_for_context(self._cap.read_cap(), ctx)

    def encrypt(self, ctx: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypts and signs plaintext for this box: (box_id, ciphertext, signature)."""
        return self._index.encrypt_for_context(self._cap, ctx, plaintext)

    def tombstone(self, ctx: bytes) -> Tuple[bytes, bytes]:
        """Signs the empty payload for this box: (box_id, signature). Written
        with an empty payload, it deletes the box."""
        return self._index.sign_box(self._cap, ctx, b"")

    def read_position(self) -> ReadPosition:
        """The read position of the same box."""
        return ReadPosition._make(self._cap.read_cap(), self._index)

    def to_bytes(self) -> bytes:
        """The write cap's bytes followed by the index's."""
        return self._cap.to_bytes() + self._index.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> "WritePosition":
        """Decodes a position, checking its index is on its cap's stream."""
        if len(data) != WriteCapSize + MessageBoxIndexSize:
            raise InvalidArgument("invalid WritePosition binary size")
        cap = WriteCap.from_bytes(data[:WriteCapSize])
        return cap.position_at(MessageBoxIndex.from_bytes(data[WriteCapSize:]))
