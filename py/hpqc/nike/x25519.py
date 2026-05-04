# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""X25519 NIKE.

Wraps libsodium's Curve25519 scalar multiplication (via PyNaCl) in
the generic NIKE API. Public and private keys are 32 bytes each;
shared secrets are 32 bytes.
"""
from __future__ import annotations

import os
from typing import Tuple

from nacl.bindings import crypto_scalarmult, crypto_scalarmult_base

from .scheme import PrivateKey, PublicKey, Scheme

_KEY_SIZE = 32


class X25519PublicKey(PublicKey):
    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        if len(data) != _KEY_SIZE:
            raise ValueError(f"X25519 public key must be {_KEY_SIZE} bytes")
        self._data = bytes(data)

    def to_bytes(self) -> bytes:
        return self._data

    @classmethod
    def from_bytes(cls, data: bytes) -> "X25519PublicKey":
        return cls(data)


class X25519PrivateKey(PrivateKey):
    __slots__ = ("_data",)

    def __init__(self, data: bytes) -> None:
        if len(data) != _KEY_SIZE:
            raise ValueError(f"X25519 private key must be {_KEY_SIZE} bytes")
        self._data = bytes(data)

    def to_bytes(self) -> bytes:
        return self._data

    @classmethod
    def from_bytes(cls, data: bytes) -> "X25519PrivateKey":
        return cls(data)

    def public_key(self) -> X25519PublicKey:
        return X25519PublicKey(crypto_scalarmult_base(self._data))


class X25519(Scheme):
    """X25519 (Curve25519) NIKE."""

    @property
    def name(self) -> str:
        return "x25519"

    @property
    def public_key_size(self) -> int:
        return _KEY_SIZE

    @property
    def private_key_size(self) -> int:
        return _KEY_SIZE

    def generate_keypair(self) -> Tuple[X25519PublicKey, X25519PrivateKey]:
        priv = X25519PrivateKey(os.urandom(_KEY_SIZE))
        return priv.public_key(), priv

    def derive_public_key(self, priv: PrivateKey) -> X25519PublicKey:
        if not isinstance(priv, X25519PrivateKey):
            raise TypeError("X25519.derive_public_key requires an X25519 private key")
        return priv.public_key()

    def derive_secret(self, priv: PrivateKey, pub: PublicKey) -> bytes:
        if not isinstance(priv, X25519PrivateKey):
            raise TypeError("X25519.derive_secret requires an X25519 private key")
        if not isinstance(pub, X25519PublicKey):
            raise TypeError("X25519.derive_secret requires an X25519 public key")
        return crypto_scalarmult(priv._data, pub._data)

    def public_key_from_bytes(self, data: bytes) -> X25519PublicKey:
        return X25519PublicKey.from_bytes(data)

    def private_key_from_bytes(self, data: bytes) -> X25519PrivateKey:
        return X25519PrivateKey.from_bytes(data)
