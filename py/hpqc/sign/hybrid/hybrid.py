# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""Hybrid signature verifier: two Scheme-shaped components composed
into one. Mirrors the on-wire layout of Go's
``github.com/katzenpost/hpqc/sign/hybrid``.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from hpqc.sign.ed25519 import Ed25519Scheme
from hpqc.sign.falcon import FalconPadded512Scheme


@runtime_checkable
class _Verifier(Protocol):
    name: str
    public_key_size: int
    signature_size: int

    def verify(
        self, public_key: bytes, message: bytes, signature: bytes
    ) -> bool: ...


class HybridSignScheme:
    """Compose two verify-only Scheme objects into one.

    Wire format matches Go's ``sign/hybrid``: the public key is the
    byte concatenation ``first_pub || second_pub`` and the signature is
    ``first_sig || second_sig``. Both halves must verify for the hybrid
    to verify; either side failing yields ``False``.
    """

    def __init__(self, name: str, first: _Verifier, second: _Verifier) -> None:
        self.name = name
        self.first = first
        self.second = second
        self.public_key_size = first.public_key_size + second.public_key_size
        self.signature_size = first.signature_size + second.signature_size

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.public_key_size:
            return False
        if len(signature) != self.signature_size:
            return False
        first_pub_end = self.first.public_key_size
        first_sig_end = self.first.signature_size
        if not self.first.verify(
            public_key[:first_pub_end], message, signature[:first_sig_end]
        ):
            return False
        return self.second.verify(
            public_key[first_pub_end:], message, signature[first_sig_end:]
        )


FalconPadded512Ed25519 = HybridSignScheme(
    "Falcon-padded-512-Ed25519",
    FalconPadded512Scheme(),
    Ed25519Scheme(),
)


__all__ = ["HybridSignScheme", "FalconPadded512Ed25519"]
