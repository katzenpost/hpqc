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

Both APIs sit on the same primitives and produce byte-identical
output; pick whichever shape suits your application.
"""
from .stateless import (
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

__all__ = [
    "BoxIDSize",
    "MessageBoxIndex",
    "MessageBoxIndexSize",
    "ReadCap",
    "ReadCapSize",
    "SignatureSize",
    "StatefulReader",
    "StatefulWriter",
    "WriteCap",
    "WriteCapSize",
]
