# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""CTIDH-2048 NIKE.

Public keys are 256 bytes, private keys are 231 bytes, shared secrets
are 256 bytes. See ``hpqc.nike._ctidh`` for the shared implementation.
"""
from __future__ import annotations

from ._ctidh import make_ctidh_classes

CTIDH2048, CTIDH2048PublicKey, CTIDH2048PrivateKey = make_ctidh_classes(2048)

__all__ = ["CTIDH2048", "CTIDH2048PublicKey", "CTIDH2048PrivateKey"]
