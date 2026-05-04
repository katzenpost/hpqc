# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Stateless BACAP types and operations.

Direct port of the stateless surface of bacap/bacap.go. The classes
here are immutable values; every cryptographic operation either
returns a new object or returns a tuple of bytes. Callers managing
sequential state across messages can either re-derive each step from
a known starting point on demand, or use the StatefulReader /
StatefulWriter wrappers in stateful.py, which simply hold a mutable
next-index pointer and advance it after each successful operation.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import os
import struct
from typing import Callable, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey as NaclVerifyKey

from hpqc.sign.ed25519 import (
    SigningKey as BlindableSigningKey,
    VerifyKey as BlindableVerifyKey,
)

from .exceptions import (
    CannotRewind,
    DecryptionFailed,
    InvalidArgument,
    SignatureVerificationFailed,
)


# Sizes mirror those declared in bacap/bacap.go.
MessageBoxIndexSize: int = 8 + 32 + 32 + 32  # 104
BoxIDSize: int = 32  # ed25519 public key
SignatureSize: int = 64  # ed25519 signature
_Ed25519PrivateKeySize: int = 64  # seed || pubkey, matching Go's encoding
WriteCapSize: int = _Ed25519PrivateKeySize + MessageBoxIndexSize  # 168
ReadCapSize: int = BoxIDSize + MessageBoxIndexSize  # 136


def _hkdf_blake2b(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-BLAKE2b-512 per RFC 5869.

    Parameter ordering matches Go's hkdf.New(blake2b.New512(nil), secret,
    salt, info). An empty salt is replaced with a hash-length zero block,
    per the RFC.
    """
    digest_size = 64
    if not salt:
        salt = b"\x00" * digest_size
    prk = hmac.new(salt, secret, hashlib.blake2b).digest()
    out = bytearray()
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.blake2b).digest()
        out += t
        counter += 1
    return bytes(out[:length])


@dataclasses.dataclass(frozen=True)
class MessageBoxIndex:
    """Position in the BACAP message-box derivation sequence.

    Wire format (104 bytes, little-endian):
      idx_64                : 8 bytes
      cur_blinding_factor   : 32 bytes
      cur_encryption_key    : 32 bytes
      hkdf_state            : 32 bytes
    """

    idx_64: int
    cur_blinding_factor: bytes  # 32 bytes
    cur_encryption_key: bytes   # 32 bytes
    hkdf_state: bytes           # 32 bytes

    def __post_init__(self) -> None:
        if not (0 <= self.idx_64 < 1 << 64):
            raise InvalidArgument("idx_64 out of range for uint64")
        for name in ("cur_blinding_factor", "cur_encryption_key", "hkdf_state"):
            v = getattr(self, name)
            if not isinstance(v, (bytes, bytearray)) or len(v) != 32:
                raise InvalidArgument(f"{name} must be 32 bytes")

    @classmethod
    def empty(cls) -> "MessageBoxIndex":
        zero = b"\x00" * 32
        return cls(0, zero, zero, zero)

    @classmethod
    def random(cls, rng: Optional[Callable[[int], bytes]] = None) -> "MessageBoxIndex":
        """Creates a freshly-randomized MessageBoxIndex.

        Picks a random HKDF state and a random starting Idx64 in
        roughly 0..2^63-2 (using the Irwin-Hall sum of two 2^62-bit
        integers strategy from the Go implementation), then advances
        once so that the returned index has properly-derived blinding
        and encryption keys.
        """
        if rng is None:
            rng = os.urandom
        hkdf_state = rng(32)
        idx_bytes = bytearray(rng(16))
        idx_bytes[0] &= 0x2F
        idx_bytes[8] &= 0x2F
        a = int.from_bytes(idx_bytes[:8], "little")
        b = int.from_bytes(idx_bytes[8:], "little")
        # Go's uint64 addition wraps on overflow; mirror that.
        idx = (a + b) & 0xFFFFFFFFFFFFFFFF
        seed = cls(idx, b"\x00" * 32, b"\x00" * 32, hkdf_state)
        return seed.next_index()

    def to_bytes(self) -> bytes:
        return (
            struct.pack("<Q", self.idx_64)
            + self.cur_blinding_factor
            + self.cur_encryption_key
            + self.hkdf_state
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "MessageBoxIndex":
        if len(data) != MessageBoxIndexSize:
            raise InvalidArgument("invalid MessageBoxIndex binary size")
        return cls(
            struct.unpack("<Q", data[:8])[0],
            bytes(data[8:40]),
            bytes(data[40:72]),
            bytes(data[72:104]),
        )

    # ----- index advancement -----

    def advance_index_to(self, target: int) -> "MessageBoxIndex":
        """Returns a new MessageBoxIndex stepped to the given idx via HKDF."""
        if target < self.idx_64:
            raise CannotRewind(
                f"cannot rewind index: target {target} < current {self.idx_64}"
            )
        if target == self.idx_64:
            return self
        cur_idx = self.idx_64
        hkdf_state = self.hkdf_state
        cur_enc_key = b"\x00" * 32
        cur_blinding = b"\x00" * 32
        while cur_idx < target:
            okm = _hkdf_blake2b(
                secret=hkdf_state,
                salt=b"",
                info=struct.pack("<Q", cur_idx),
                length=96,
            )
            hkdf_state = okm[:32]
            cur_enc_key = okm[32:64]
            cur_blinding = okm[64:96]
            cur_idx += 1
        return MessageBoxIndex(cur_idx, cur_blinding, cur_enc_key, hkdf_state)

    def next_index(self) -> "MessageBoxIndex":
        return self.advance_index_to(self.idx_64 + 1)

    # ----- box-ID derivation -----

    def derive_message_box_id(self, root_public_key: BlindableVerifyKey) -> bytes:
        """Returns the blinded box-ID public key (32 bytes)."""
        return bytes(root_public_key.blind(self.cur_blinding_factor))

    def _derive_k_for_context(self, ctx: bytes) -> bytes:
        return _hkdf_blake2b(
            secret=self.cur_blinding_factor,
            salt=ctx,
            info=b"",
            length=32,
        )

    def _derive_e_for_context(self, ctx: bytes) -> bytes:
        return _hkdf_blake2b(
            secret=self.cur_encryption_key,
            salt=ctx,
            info=b"",
            length=32,
        )

    def box_id_for_context(self, read_cap: "ReadCap", ctx: bytes) -> bytes:
        """Returns the box ID (32-byte blinded ed25519 pubkey) for ctx."""
        k_ctx = self._derive_k_for_context(ctx)
        return bytes(read_cap.root_public_key.blind(k_ctx))

    # ----- sign / verify -----

    def sign_box(
        self, owner: "WriteCap", ctx: bytes, ciphertext: bytes
    ) -> Tuple[bytes, bytes]:
        """Signs ciphertext under the blinded private key for this index+ctx.

        Returns (box_id, signature). The signature verifies under standard
        Ed25519 against box_id, so any standards-compliant verifier works.
        """
        k_ctx = self._derive_k_for_context(ctx)
        box_id = bytes(owner.root_public_key.blind(k_ctx))
        blinded_priv = owner.root_private_key.blind(k_ctx)
        sig = blinded_priv.sign(ciphertext)[:64]
        return box_id, sig

    @staticmethod
    def verify_box(box: bytes, ciphertext: bytes, signature: bytes) -> bool:
        """Returns True iff signature verifies under box (the box-ID pubkey)."""
        if len(box) != BoxIDSize:
            raise InvalidArgument("invalid box length")
        try:
            NaclVerifyKey(box).verify(ciphertext, signature)
        except BadSignatureError:
            return False
        return True

    # ----- encrypt / decrypt -----

    def encrypt_for_context(
        self, owner: "WriteCap", ctx: bytes, plaintext: bytes
    ) -> Tuple[bytes, bytes, bytes]:
        """Encrypts plaintext for this index+ctx.

        Returns (box_id, ciphertext, signature). The signature is over the
        ciphertext, made by the blinded private key whose corresponding
        blinded pubkey is box_id.
        """
        k_ctx = self._derive_k_for_context(ctx)
        box_id = bytes(owner.root_public_key.blind(k_ctx))
        e_ctx = self._derive_e_for_context(ctx)
        nonce = box_id[:12]
        aad = box_id
        ciphertext = AESGCMSIV(e_ctx).encrypt(nonce, plaintext, aad)
        blinded_priv = owner.root_private_key.blind(k_ctx)
        sig = blinded_priv.sign(ciphertext)[:64]
        return box_id, ciphertext, sig

    def decrypt_for_context(
        self,
        box: bytes,
        ctx: bytes,
        ciphertext: bytes,
        signature: bytes,
    ) -> bytes:
        """Verifies signature, then AES-GCM-SIV-decrypts ciphertext.

        An empty ciphertext is treated as a tombstone: the signature is
        verified over the empty payload and an empty plaintext is returned
        without any decryption.
        """
        if len(box) != BoxIDSize:
            raise InvalidArgument("invalid box length")
        try:
            NaclVerifyKey(box).verify(ciphertext, signature)
        except BadSignatureError as e:
            raise SignatureVerificationFailed(
                "signature did not verify under the box-ID public key"
            ) from e
        if not ciphertext:
            return b""
        e_ctx = self._derive_e_for_context(ctx)
        try:
            return AESGCMSIV(e_ctx).decrypt(box[:12], ciphertext, box)
        except InvalidTag as e:
            raise DecryptionFailed("AES-256-GCM-SIV authentication failed") from e


def _seed_from_signing_key(sk: BlindableSigningKey) -> bytes:
    """Returns the 32-byte ed25519 seed from a SigningKey."""
    return bytes(sk)


def _ed25519_64byte_private(sk: BlindableSigningKey) -> bytes:
    """Returns the 64-byte (seed||pubkey) form of an ed25519 private key.

    Matches Go's crypto/ed25519 marshaling so that WriteCap.to_bytes()
    is byte-identical to the Go side's WriteCap.MarshalBinary().
    """
    return _seed_from_signing_key(sk) + bytes(sk.verify_key)


@dataclasses.dataclass(frozen=True)
class WriteCap:
    """Holds the root private key plus the conversation's first MessageBoxIndex.

    The bearer of a WriteCap can derive the full box ID sequence and the
    corresponding signing keys; deriving a ReadCap from it gives someone
    else the ability to read but not write.
    """

    root_private_key: BlindableSigningKey
    first_message_box_index: MessageBoxIndex

    @property
    def root_public_key(self) -> BlindableVerifyKey:
        return self.root_private_key.verify_key

    @classmethod
    def generate(
        cls,
        rng: Optional[Callable[[int], bytes]] = None,
    ) -> "WriteCap":
        """Returns a new WriteCap with a fresh random keypair and first index."""
        if rng is None:
            rng = os.urandom
        sk = BlindableSigningKey(rng(32))
        return cls(sk, MessageBoxIndex.random(rng))

    def to_bytes(self) -> bytes:
        return _ed25519_64byte_private(self.root_private_key) + self.first_message_box_index.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "WriteCap":
        if len(data) != WriteCapSize:
            raise InvalidArgument("invalid WriteCap binary size")
        # Go stores seed||pubkey; we re-derive pubkey from seed and ignore
        # the stored pubkey (it is implied by the seed).
        sk = BlindableSigningKey(data[:32])
        idx = MessageBoxIndex.from_bytes(data[_Ed25519PrivateKeySize:])
        return cls(sk, idx)

    def read_cap(self) -> "ReadCap":
        """Returns the ReadCap derived from this WriteCap."""
        return ReadCap(self.root_public_key, self.first_message_box_index)

    def derive_box_id(self, message_box_index: MessageBoxIndex) -> bytes:
        return message_box_index.derive_message_box_id(self.root_public_key)


@dataclasses.dataclass(frozen=True)
class ReadCap:
    """Holds the root public key plus the conversation's first MessageBoxIndex.

    The bearer can derive the full box-ID sequence and verify+decrypt
    messages, but cannot sign new ones.
    """

    root_public_key: BlindableVerifyKey
    first_message_box_index: MessageBoxIndex

    def to_bytes(self) -> bytes:
        return bytes(self.root_public_key) + self.first_message_box_index.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "ReadCap":
        if len(data) != ReadCapSize:
            raise InvalidArgument("invalid ReadCap binary size")
        pk = BlindableVerifyKey(data[:BoxIDSize])
        idx = MessageBoxIndex.from_bytes(data[BoxIDSize:])
        return cls(pk, idx)

    def derive_box_id(self, message_box_index: MessageBoxIndex) -> bytes:
        return message_box_index.derive_message_box_id(self.root_public_key)
