# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Python port of katzenpost/hpqc/bacap.

The package exposes two complementary APIs:

  - **Stateless** (``hpqc.bacap.stateless``): ``MessageBoxIndex``,
    ``WriteCap`` and ``ReadCap`` are pure values; every cryptographic
    operation is a method that takes its inputs and returns its
    outputs without mutating the caller's state. Suitable for callers
    that already manage the per-conversation state themselves and want
    a thin layer over the BACAP primitives.

  - **Stateful** (``hpqc.bacap.stateful``): ``StatefulReader`` and
    ``StatefulWriter`` are mutable wrappers built on the stateless
    layer. They carry the next-index pointer and advance it after each
    successful read or write, mirroring the Go API.

  - **Positions** (``hpqc.bacap.positions``): ``ReadPosition`` and
    ``WritePosition`` bind a capability to one box on its stream, so a
    capability is never paired with another stream's index. Get one from
    ``start`` or ``position_at`` on a cap. The recommended API, mirroring
    Go's.

All of them sit on the same primitives and produce byte-identical output.
"""
from .exceptions import (
    BACAPError,
    BoxIDMismatch,
    CannotRewind,
    DecryptionFailed,
    EmptyBox,
    IndexNotInChannel,
    IndexTooFar,
    InvalidArgument,
    SignatureVerificationFailed,
)
from .stateless import (
    MAX_CONTAINS_WALK,
    BoxIDSize,
    MessageBoxIndex,
    MessageBoxIndexSize,
    ReadCap,
    ReadCapSize,
    SignatureSize,
    WriteCap,
    WriteCapSize,
)
from .stateful import StatefulReader, StatefulWriter
from .positions import ReadPosition, WritePosition

__all__ = [
    # exceptions
    "BACAPError",
    "BoxIDMismatch",
    "CannotRewind",
    "DecryptionFailed",
    "EmptyBox",
    "IndexNotInChannel",
    "IndexTooFar",
    "InvalidArgument",
    "SignatureVerificationFailed",
    # stateless
    "MAX_CONTAINS_WALK",
    "BoxIDSize",
    "MessageBoxIndex",
    "MessageBoxIndexSize",
    "ReadCap",
    "ReadCapSize",
    "SignatureSize",
    "WriteCap",
    "WriteCapSize",
    # stateful
    "StatefulReader",
    "StatefulWriter",
    # positions
    "ReadPosition",
    "WritePosition",
]
