# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""CTIDH-512 NIKE.

Public keys are 64 bytes, private keys are 74 bytes, shared secrets
are 64 bytes. See ``hpqc.nike._ctidh`` for the shared implementation.
"""
from __future__ import annotations

from ._ctidh import make_ctidh_classes

CTIDH512, CTIDH512PublicKey, CTIDH512PrivateKey = make_ctidh_classes(512)

__all__ = ["CTIDH512", "CTIDH512PublicKey", "CTIDH512PrivateKey"]
