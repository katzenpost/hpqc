# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""CTIDH-1024 NIKE.

Public keys are 128 bytes, private keys are 130 bytes, shared secrets
are 128 bytes. See ``hpqc.nike._ctidh`` for the shared implementation.
"""
from __future__ import annotations

from ._ctidh import make_ctidh_classes

CTIDH1024, CTIDH1024PublicKey, CTIDH1024PrivateKey = make_ctidh_classes(1024)

__all__ = ["CTIDH1024", "CTIDH1024PublicKey", "CTIDH1024PrivateKey"]
