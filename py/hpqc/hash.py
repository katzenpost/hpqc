# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""hpqc.hash — BLAKE2b-256 helper, mirroring the Go ``hash`` package.

The Go side at ``hpqc/hash/hash.go`` exposes ``HashSize`` (32) and
``Sum256``. This Python module exposes the same surface in
snake_case and is imported by ``hpqc.kem.mkem``.
"""
from __future__ import annotations

import hashlib

#: Size in bytes of the BLAKE2b-256 output.
HashSize: int = 32


def sum256(data: bytes) -> bytes:
    """Returns BLAKE2b-256 of ``data`` as a 32-byte ``bytes`` object."""
    return hashlib.blake2b(data, digest_size=HashSize).digest()
