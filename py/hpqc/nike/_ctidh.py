# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Internal CTIDH NIKE factory shared across field sizes.

CTIDH at every supported field size (511, 512, 1024, 2048) is the same
construction applied over a different underlying prime. The high-level
adapter is identical apart from the field_size constant. Rather than
copy-paste the wrapper four times, ``make_ctidh_classes(field_size)``
builds a fresh ``(SchemeClass, PublicKeyClass, PrivateKeyClass)``
triple bound to that size. Each call returns *distinct* classes, so
``isinstance`` continues to catch attempts to mix keys across field
sizes (a CTIDH-1024 public key is not a CTIDH-511 public key).
"""
from __future__ import annotations

from typing import Callable, Tuple, Type

from highctidh import ctidh as _ctidh

from .scheme import PrivateKey, PublicKey, Scheme


def _raw_bytes(shared, size: int) -> bytes:  # noqa: ARG001
    """Identity ``_hash`` for highctidh's dh(): return raw point bytes."""
    return bytes(shared)


def make_ctidh_classes(
    field_size: int,
) -> Tuple[Type[Scheme], Type[PublicKey], Type[PrivateKey]]:
    """Returns (SchemeClass, PublicKeyClass, PrivateKeyClass) for the
    requested CTIDH field size. The underlying highctidh instance is
    closed over per call, and each call produces fresh classes so
    type-safety checks via ``isinstance`` distinguish keys across sizes.
    """
    impl = _ctidh(field_size)
    name = f"ctidh{field_size}"

    class CTIDHPublicKey(PublicKey):
        __slots__ = ("_inner",)

        def __init__(self, inner) -> None:
            self._inner = inner

        def to_bytes(self) -> bytes:
            return bytes(self._inner)

        @classmethod
        def from_bytes(cls, data: bytes) -> "CTIDHPublicKey":
            return cls(impl.public_key_from_bytes(data))

    class CTIDHPrivateKey(PrivateKey):
        __slots__ = ("_inner",)

        def __init__(self, inner) -> None:
            self._inner = inner

        def to_bytes(self) -> bytes:
            return bytes(self._inner)

        @classmethod
        def from_bytes(cls, data: bytes) -> "CTIDHPrivateKey":
            return cls(impl.private_key_from_bytes(data))

        def public_key(self) -> CTIDHPublicKey:
            return CTIDHPublicKey(impl.derive_public_key(self._inner))

    class CTIDHScheme(Scheme):
        @property
        def name(self) -> str:
            return name

        @property
        def public_key_size(self) -> int:
            return impl.pk_size

        @property
        def private_key_size(self) -> int:
            return impl.sk_size

        def generate_keypair(self) -> Tuple[CTIDHPublicKey, CTIDHPrivateKey]:
            sk = impl.generate_secret_key()
            pk = impl.derive_public_key(sk)
            return CTIDHPublicKey(pk), CTIDHPrivateKey(sk)

        def generate_keypair_from_entropy(
            self, read: Callable[[int], bytes]
        ) -> Tuple[CTIDHPublicKey, CTIDHPrivateKey]:
            # highctidh fills ``buf`` (a uint8 memoryview) per rejection-
            # sampling round; ``read`` must return exactly len(buf) bytes.
            # Feeding the same byte stream to the Go binding's
            # GenerateKeyPairFromEntropy yields a byte-identical key, which
            # is what makes the cross-language voucher vectors possible.
            def fill(buf, context) -> None:  # noqa: ANN001 - highctidh callback
                buf[:] = read(len(buf))

            sk = impl.generate_secret_key(rng=fill)
            pk = impl.derive_public_key(sk)
            return CTIDHPublicKey(pk), CTIDHPrivateKey(sk)

        def derive_public_key(self, priv: PrivateKey) -> CTIDHPublicKey:
            if not isinstance(priv, CTIDHPrivateKey):
                raise TypeError(f"{name}.derive_public_key requires a {name} private key")
            return priv.public_key()

        def derive_secret(self, priv: PrivateKey, pub: PublicKey) -> bytes:
            if not isinstance(priv, CTIDHPrivateKey):
                raise TypeError(f"{name}.derive_secret requires a {name} private key")
            if not isinstance(pub, CTIDHPublicKey):
                raise TypeError(f"{name}.derive_secret requires a {name} public key")
            # highctidh's high-level dh() defaults to SHAKE256-hashing the
            # shared point; the Go side at hpqc/nike/ctidh/<size> returns
            # the raw point bytes (the canonical NIKE-shared-secret
            # convention used throughout hpqc). We override _hash with the
            # identity function so we get the raw bytes too.
            return impl.dh(priv._inner, pub._inner, _hash=_raw_bytes)

        def public_key_from_bytes(self, data: bytes) -> CTIDHPublicKey:
            return CTIDHPublicKey.from_bytes(data)

        def private_key_from_bytes(self, data: bytes) -> CTIDHPrivateKey:
            return CTIDHPrivateKey.from_bytes(data)

    # Cosmetic: give the generated classes recognisable names in
    # tracebacks and ``repr`` instead of all looking like CTIDHScheme.
    CTIDHScheme.__name__ = f"CTIDH{field_size}"
    CTIDHScheme.__qualname__ = CTIDHScheme.__name__
    CTIDHPublicKey.__name__ = f"CTIDH{field_size}PublicKey"
    CTIDHPublicKey.__qualname__ = CTIDHPublicKey.__name__
    CTIDHPrivateKey.__name__ = f"CTIDH{field_size}PrivateKey"
    CTIDHPrivateKey.__qualname__ = CTIDHPrivateKey.__name__

    return CTIDHScheme, CTIDHPublicKey, CTIDHPrivateKey
