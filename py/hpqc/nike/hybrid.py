# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""NIKE combiner: a hybrid scheme built from two NIKE schemes.

Wraps two component schemes (e.g. CTIDH1024 and X25519) and exposes
the same NIKE interface. Public/private keys are the concatenation
of the component keys; the shared secret is the concatenation of the
component shared secrets, matching the byte-for-byte behaviour of
``github.com/katzenpost/hpqc/nike/hybrid``.

Concatenation is the simplest combiner: it is collision-resistant
(two distinct hybrid keys differ in at least one component) but it
is not a "security-preserving" combiner in the formal sense. For
NIKE-as-NIKE that is normally fine; for KEM combiners, the same
construction is *not* sufficient and a hash-based combiner is
required. See ``hpqc/kem/combiner`` on the Go side for that case.
"""
from __future__ import annotations

from typing import Tuple

from .scheme import PrivateKey, PublicKey, Scheme


class HybridPublicKey(PublicKey):
    """Public key of a HybridNIKE: ``first_pubkey || second_pubkey``."""

    __slots__ = ("_first", "_second", "_scheme")

    def __init__(
        self,
        first: PublicKey,
        second: PublicKey,
        scheme: "HybridNIKE",
    ) -> None:
        self._first = first
        self._second = second
        self._scheme = scheme

    @property
    def first(self) -> PublicKey:
        return self._first

    @property
    def second(self) -> PublicKey:
        return self._second

    def to_bytes(self) -> bytes:
        return self._first.to_bytes() + self._second.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridPublicKey":
        # Cannot reconstruct without knowing the scheme; callers should
        # use HybridNIKE.public_key_from_bytes instead.
        raise NotImplementedError(
            "use HybridNIKE.public_key_from_bytes(data) to deserialise"
        )


class HybridPrivateKey(PrivateKey):
    """Private key of a HybridNIKE: ``first_privkey || second_privkey``."""

    __slots__ = ("_first", "_second", "_scheme")

    def __init__(
        self,
        first: PrivateKey,
        second: PrivateKey,
        scheme: "HybridNIKE",
    ) -> None:
        self._first = first
        self._second = second
        self._scheme = scheme

    @property
    def first(self) -> PrivateKey:
        return self._first

    @property
    def second(self) -> PrivateKey:
        return self._second

    def to_bytes(self) -> bytes:
        return self._first.to_bytes() + self._second.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridPrivateKey":
        raise NotImplementedError(
            "use HybridNIKE.private_key_from_bytes(data) to deserialise"
        )

    def public_key(self) -> HybridPublicKey:
        return HybridPublicKey(
            self._first.public_key(),
            self._second.public_key(),
            self._scheme,
        )


class HybridNIKE(Scheme):
    """A NIKE composed of two underlying NIKEs.

    The resulting scheme has:

      - ``public_key_size  = first.public_key_size  + second.public_key_size``
      - ``private_key_size = first.private_key_size + second.private_key_size``
      - shared secret      = ``first.derive_secret(...) || second.derive_secret(...)``

    Serialised hybrid keys are the byte concatenation of the
    components, in (first, second) order. Round-trip
    deserialisation goes through the scheme's
    ``public_key_from_bytes`` / ``private_key_from_bytes`` methods,
    which know each component's sub-scheme and the byte boundary.
    """

    def __init__(self, first: Scheme, second: Scheme) -> None:
        self._first = first
        self._second = second

    @property
    def first(self) -> Scheme:
        return self._first

    @property
    def second(self) -> Scheme:
        return self._second

    @property
    def name(self) -> str:
        return f"{self._first.name}-{self._second.name}"

    @property
    def public_key_size(self) -> int:
        return self._first.public_key_size + self._second.public_key_size

    @property
    def private_key_size(self) -> int:
        return self._first.private_key_size + self._second.private_key_size

    def generate_keypair(self) -> Tuple[HybridPublicKey, HybridPrivateKey]:
        pub1, priv1 = self._first.generate_keypair()
        pub2, priv2 = self._second.generate_keypair()
        return (
            HybridPublicKey(pub1, pub2, self),
            HybridPrivateKey(priv1, priv2, self),
        )

    def derive_public_key(self, priv: PrivateKey) -> HybridPublicKey:
        if not isinstance(priv, HybridPrivateKey) or priv._scheme is not self:
            raise TypeError(
                "HybridNIKE.derive_public_key requires a HybridPrivateKey from this scheme"
            )
        return HybridPublicKey(
            self._first.derive_public_key(priv._first),
            self._second.derive_public_key(priv._second),
            self,
        )

    def derive_secret(self, priv: PrivateKey, pub: PublicKey) -> bytes:
        if not isinstance(priv, HybridPrivateKey) or priv._scheme is not self:
            raise TypeError(
                "HybridNIKE.derive_secret requires a HybridPrivateKey from this scheme"
            )
        if not isinstance(pub, HybridPublicKey) or pub._scheme is not self:
            raise TypeError(
                "HybridNIKE.derive_secret requires a HybridPublicKey from this scheme"
            )
        return (
            self._first.derive_secret(priv._first, pub._first)
            + self._second.derive_secret(priv._second, pub._second)
        )

    def public_key_from_bytes(self, data: bytes) -> HybridPublicKey:
        if len(data) != self.public_key_size:
            raise ValueError(
                f"hybrid public key must be {self.public_key_size} bytes"
            )
        n = self._first.public_key_size
        return HybridPublicKey(
            self._first.public_key_from_bytes(data[:n]),
            self._second.public_key_from_bytes(data[n:]),
            self,
        )

    def private_key_from_bytes(self, data: bytes) -> HybridPrivateKey:
        if len(data) != self.private_key_size:
            raise ValueError(
                f"hybrid private key must be {self.private_key_size} bytes"
            )
        n = self._first.private_key_size
        return HybridPrivateKey(
            self._first.private_key_from_bytes(data[:n]),
            self._second.private_key_from_bytes(data[n:]),
            self,
        )
