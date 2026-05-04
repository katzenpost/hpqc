# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""CTIDH-511 NIKE.

Public keys are 64 bytes, private keys are 74 bytes, shared secrets
are 64 bytes. See ``hpqc.nike._ctidh`` for the shared implementation.
"""
from __future__ import annotations

from ._ctidh import make_ctidh_classes

CTIDH511, CTIDH511PublicKey, CTIDH511PrivateKey = make_ctidh_classes(511)

__all__ = ["CTIDH511", "CTIDH511PublicKey", "CTIDH511PrivateKey"]
