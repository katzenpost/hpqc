# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Sealed box: anonymous public-key encryption to a single recipient.

Direct port of ``hpqc/protocols/sealedbox`` on the Go side. A sealed
box in the sense of libsodium's ``crypto_box_seal``, generalised from
X25519 to any NIKE scheme, so that a post-quantum hybrid NIKE such as
X25519-CTIDH1024 can be used in its place. The sender is not
authenticated: the recipient learns nothing about who sealed a box.
The key derivation differs from libsodium's, so even over X25519 the
two are not interoperable.

A sealed box is ``eph_pub || secretbox(plaintext)``. A fresh ephemeral
keypair is generated for every box, so the XSalsa20-Poly1305 key and
nonce, both derived from the shared secret, are each used exactly once
and the nonce is never transmitted::

    okm   = HKDF-BLAKE2b-256(ss, salt = nil,
                             info = "hpqc-nike-sealedbox-v1" || uint16be(len(name))
                                    || name || eph_pub || recipient_pub)
    key   = okm[0:32]
    nonce = okm[32:56]
"""
from __future__ import annotations

import functools
import hashlib
import hmac
import os
from typing import Callable

from nacl.exceptions import CryptoError
from nacl.secret import SecretBox

from hpqc.nike.scheme import PrivateKey, PublicKey, Scheme as NIKEScheme

_KDF_LABEL = b"hpqc-nike-sealedbox-v1"
_KEY_SIZE = 32
_NONCE_SIZE = 24
_TAG_SIZE = 16

_blake2b_256 = functools.partial(hashlib.blake2b, digest_size=32)


class SealedBoxError(Exception):
    """Base class of every sealed box error."""


class OpenError(SealedBoxError):
    """A box failed to open. Opening never says which check failed."""


class DegenerateSharedSecretError(SealedBoxError):
    """The NIKE shared secret is all zero."""


class KeySchemeError(SealedBoxError):
    """A key is ``None`` or does not belong to the scheme's NIKE."""


def _hkdf_blake2b_256(secret: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(b"\x00" * 32, secret, _blake2b_256).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), _blake2b_256).digest()
        out += t
        counter += 1
    return bytes(out[:length])


class SealedBoxScheme:
    """A sealed box scheme over one NIKE."""

    def __init__(self, nike: NIKEScheme) -> None:
        self._nike = nike

    @property
    def name(self) -> str:
        """``"sealedbox-"`` followed by the NIKE name."""
        return "sealedbox-" + self._nike.name

    @property
    def overhead(self) -> int:
        """Number of bytes a box adds to its plaintext."""
        return self._nike.public_key_size + _TAG_SIZE

    def seal(self, recipient: PublicKey, plaintext: bytes) -> bytes:
        """Encrypts ``plaintext`` to ``recipient`` under a fresh ephemeral key."""
        return self.seal_with_entropy(recipient, plaintext, os.urandom)

    def seal_with_entropy(
        self,
        recipient: PublicKey,
        plaintext: bytes,
        read: Callable[[int], bytes],
    ) -> bytes:
        """``seal`` with the ephemeral keypair drawn from ``read``.

        It exists to build reproducible test vectors. The key and nonce
        are derived from the ephemeral key, so a source that repeats its
        output repeats them too, and two boxes to one recipient under the
        same key and nonce reveal the XOR of their plaintexts. Use
        ``seal`` otherwise.
        """
        if recipient is None:
            raise KeySchemeError("sealedbox: key is not of this NIKE scheme")
        eph_pub, eph_priv = self._nike.generate_keypair_from_entropy(read)
        eph_pub_bytes = eph_pub.to_bytes()
        key, nonce = self._derive_keys(eph_priv, recipient, eph_pub_bytes, recipient.to_bytes())
        return eph_pub_bytes + SecretBox(key).encrypt(plaintext, nonce).ciphertext

    def open(self, priv: PrivateKey, pub: PublicKey, ciphertext: bytes) -> bytes:
        """Decrypts a box sealed to ``pub``, the public key of ``priv``.

        ``pub`` is passed in rather than derived because deriving it costs
        as much as the key agreement for CSIDH-based NIKEs. A ``pub`` that
        does not match ``priv`` makes every box fail to open. Every
        failure raises ``OpenError``.
        """
        if priv is None or pub is None:
            raise OpenError("sealedbox: open failed")
        pk_size = self._nike.public_key_size
        if len(ciphertext) < pk_size + _TAG_SIZE:
            raise OpenError("sealedbox: open failed")
        eph_pub_bytes = bytes(ciphertext[:pk_size])
        try:
            eph_pub = self._nike.public_key_from_bytes(eph_pub_bytes)
            key, nonce = self._derive_keys(priv, eph_pub, eph_pub_bytes, pub.to_bytes())
            return SecretBox(key).decrypt(bytes(ciphertext[pk_size:]), nonce)
        except (SealedBoxError, CryptoError, ValueError, TypeError, RuntimeError) as e:
            raise OpenError("sealedbox: open failed") from e

    def _derive_keys(
        self,
        priv: PrivateKey,
        pub: PublicKey,
        eph_pub: bytes,
        recipient_pub: bytes,
    ) -> tuple[bytes, bytes]:
        if len(recipient_pub) != self._nike.public_key_size:
            raise KeySchemeError("sealedbox: key is not of this NIKE scheme")
        try:
            ss = self._nike.derive_secret(priv, pub)
        except TypeError as e:
            raise KeySchemeError("sealedbox: key is not of this NIKE scheme") from e
        except (ValueError, RuntimeError) as e:
            # libsodium refuses an X25519 result of zero, which the Go side
            # reports as a degenerate secret.
            raise DegenerateSharedSecretError(
                "sealedbox: degenerate all-zero shared secret"
            ) from e
        if not any(ss):
            raise DegenerateSharedSecretError("sealedbox: degenerate all-zero shared secret")

        name = self._nike.name.encode()
        info = _KDF_LABEL + len(name).to_bytes(2, "big") + name + eph_pub + recipient_pub
        okm = _hkdf_blake2b_256(ss, info, _KEY_SIZE + _NONCE_SIZE)
        return okm[:_KEY_SIZE], okm[_KEY_SIZE:]
