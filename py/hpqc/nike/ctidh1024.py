# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""CTIDH-1024 NIKE.

Wraps the CTIDH (Commutative Supersingular Isogeny Diffie-Hellman)
implementation from highctidh in the generic NIKE API. Public keys
are 128 bytes, private keys are 130 bytes, and shared secrets are
128 bytes (the size of the underlying field element).

The cryptography here is the work of others; this module is only a
thin adapter so CTIDH-1024 can be passed around as a ``nike.Scheme``
alongside X25519 or composed via ``hpqc.nike.hybrid.HybridNIKE``.
"""
from __future__ import annotations

from typing import Tuple

from highctidh import ctidh as _ctidh

from .scheme import PrivateKey, PublicKey, Scheme

# A single shared underlying instance per process. The highctidh
# ``ctidh(field_size)`` object is a stateless namespace of operations
# bound to the field size; instantiating it once is sufficient.
_CTIDH = _ctidh(1024)


class CTIDH1024PublicKey(PublicKey):
    """CTIDH-1024 public key (128 bytes when serialised)."""

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:  # inner is a highctidh public_key
        self._inner = inner

    def to_bytes(self) -> bytes:
        return bytes(self._inner)

    @classmethod
    def from_bytes(cls, data: bytes) -> "CTIDH1024PublicKey":
        return cls(_CTIDH.public_key_from_bytes(data))


class CTIDH1024PrivateKey(PrivateKey):
    """CTIDH-1024 private key (130 bytes when serialised)."""

    __slots__ = ("_inner",)

    def __init__(self, inner) -> None:  # inner is a highctidh private_key
        self._inner = inner

    def to_bytes(self) -> bytes:
        return bytes(self._inner)

    @classmethod
    def from_bytes(cls, data: bytes) -> "CTIDH1024PrivateKey":
        return cls(_CTIDH.private_key_from_bytes(data))

    def public_key(self) -> CTIDH1024PublicKey:
        return CTIDH1024PublicKey(_CTIDH.derive_public_key(self._inner))


class CTIDH1024(Scheme):
    """CTIDH-1024 NIKE (post-quantum, isogeny-based)."""

    @property
    def name(self) -> str:
        return "ctidh1024"

    @property
    def public_key_size(self) -> int:
        return _CTIDH.pk_size

    @property
    def private_key_size(self) -> int:
        return _CTIDH.sk_size

    def generate_keypair(self) -> Tuple[CTIDH1024PublicKey, CTIDH1024PrivateKey]:
        sk = _CTIDH.generate_secret_key()
        pk = _CTIDH.derive_public_key(sk)
        return CTIDH1024PublicKey(pk), CTIDH1024PrivateKey(sk)

    def derive_public_key(self, priv: PrivateKey) -> CTIDH1024PublicKey:
        if not isinstance(priv, CTIDH1024PrivateKey):
            raise TypeError("CTIDH1024.derive_public_key requires a CTIDH1024 private key")
        return priv.public_key()

    def derive_secret(self, priv: PrivateKey, pub: PublicKey) -> bytes:
        if not isinstance(priv, CTIDH1024PrivateKey):
            raise TypeError("CTIDH1024.derive_secret requires a CTIDH1024 private key")
        if not isinstance(pub, CTIDH1024PublicKey):
            raise TypeError("CTIDH1024.derive_secret requires a CTIDH1024 public key")
        return bytes(_CTIDH.dh(priv._inner, pub._inner))

    def public_key_from_bytes(self, data: bytes) -> CTIDH1024PublicKey:
        return CTIDH1024PublicKey.from_bytes(data)

    def private_key_from_bytes(self, data: bytes) -> CTIDH1024PrivateKey:
        return CTIDH1024PrivateKey.from_bytes(data)
