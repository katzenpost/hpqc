# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Sanity tests for the BLAKE2b-256 helper in hpqc.hash."""
from __future__ import annotations

import hashlib

from hpqc.hash import HashSize, sum256


def test_hashsize_constant() -> None:
    assert HashSize == 32


def test_sum256_matches_hashlib_blake2b_256() -> None:
    for data in (b"", b"abc", b"\x00" * 32, b"hpqc test vector"):
        assert sum256(data) == hashlib.blake2b(data, digest_size=32).digest()


def test_sum256_returns_32_bytes() -> None:
    assert len(sum256(b"x")) == HashSize
