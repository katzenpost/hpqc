# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Abstract base classes for the NIKE (non-interactive key exchange) API.

Mirrors the Go interfaces in ``hpqc/nike/nike.go``. Any object that
satisfies these contracts can be used interchangeably with any
implementation: X25519, CTIDH1024, or a hybrid built from two of them.

Python equivalent of Go interfaces: we use ``abc.ABC`` with abstract
methods. This is the dominant pattern in the standard library and in
mature Python crypto libraries (``cryptography.hazmat.primitives``
uses it throughout). An alternative is ``typing.Protocol`` (PEP 544),
which gives Go-style structural typing, but ABCs read more clearly
when implementations live inside the package and you want
``isinstance`` checks at runtime.

A NIKE has three roles, the Python names map directly onto Go's:

  - ``PrivateKey`` / ``PublicKey`` are the key types. Each
    implementation provides its own concrete class.
  - ``Scheme`` is the namespace of operations: keypair generation,
    shared-secret derivation, and (de)serialisation. Schemes are
    typically instantiated once and passed around as values.
"""
from __future__ import annotations

import abc
from typing import TYPE_CHECKING, Tuple

if TYPE_CHECKING:
    from typing import Self


class PublicKey(abc.ABC):
    """A NIKE public key."""

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        """Serialises the public key to its canonical byte form."""

    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, data: bytes) -> "Self":
        """Deserialises the public key from canonical bytes."""

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PublicKey):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash(self.to_bytes())


class PrivateKey(abc.ABC):
    """A NIKE private key."""

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        """Serialises the private key to its canonical byte form."""

    @classmethod
    @abc.abstractmethod
    def from_bytes(cls, data: bytes) -> "Self":
        """Deserialises the private key from canonical bytes."""

    @abc.abstractmethod
    def public_key(self) -> PublicKey:
        """Returns the public key corresponding to this private key."""

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PrivateKey):
            return NotImplemented
        return self.to_bytes() == other.to_bytes()

    def __hash__(self) -> int:
        return hash(self.to_bytes())


class Scheme(abc.ABC):
    """A non-interactive key exchange scheme.

    Each scheme owns its own ``PrivateKey`` / ``PublicKey`` types.
    The keys returned by one scheme are not interchangeable with
    those of another, even if the byte sizes happen to match.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Stable identifier for the scheme, e.g. ``"x25519"``."""

    @property
    @abc.abstractmethod
    def public_key_size(self) -> int:
        """Size in bytes of the canonical public key encoding."""

    @property
    @abc.abstractmethod
    def private_key_size(self) -> int:
        """Size in bytes of the canonical private key encoding."""

    @abc.abstractmethod
    def generate_keypair(self) -> Tuple[PublicKey, PrivateKey]:
        """Returns a freshly-generated (public, private) pair."""

    @abc.abstractmethod
    def derive_public_key(self, priv: PrivateKey) -> PublicKey:
        """Returns the public key corresponding to the given private key."""

    @abc.abstractmethod
    def derive_secret(self, priv: PrivateKey, pub: PublicKey) -> bytes:
        """Returns the shared secret for one party's private key and the
        other party's public key. Both parties produce the same output
        when applied to swapped key roles.
        """

    @abc.abstractmethod
    def public_key_from_bytes(self, data: bytes) -> PublicKey:
        """Deserialises a public key in this scheme."""

    @abc.abstractmethod
    def private_key_from_bytes(self, data: bytes) -> PrivateKey:
        """Deserialises a private key in this scheme."""
