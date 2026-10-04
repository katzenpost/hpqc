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
    BoxIDMismatch,
    CannotRewind,
    DecryptionFailed,
    EmptyBox,
    IndexNotInChannel,
    IndexTooFar,
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

# HKDF info (domain-separation) label for MutateKDFState. Must match the Go
# constant bacap.mutateKDFStateLabel so the two ports agree byte-for-byte.
_MUTATE_KDF_STATE_LABEL: bytes = b"bacap-mutate-kdf-state-v1"


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
        # Each half is read little-endian, so its most-significant
        # byte is the last one (index 7 / index 15), not the first.
        # Clear the top two bits of that byte (0x3F = 0b00111111) to
        # bound each half to [0, 2^62 - 1]; the sum is then in
        # [0, 2^63 - 2], leaving at least 2^63 usable indices. Masking
        # idx_bytes[0]/idx_bytes[8] (the least-significant bytes) left
        # the high bytes random, so idx reached ~2^64.
        idx_bytes[7] &= 0x3F
        idx_bytes[15] &= 0x3F
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

    def mutate_kdf_state(self, ctx: bytes) -> "MessageBoxIndex":
        """Returns a copy with its KDF ratchet state re-seeded by ctx.

        Mixes the current hkdf_state with ctx through HKDF-BLAKE2b under a
        dedicated domain label, then re-derives the per-box encryption key and
        blinding factor (read order H, E, K, matching advance_index_to);
        idx_64 is preserved. The mutated index addresses a fresh sequence of
        boxes that cannot be found without ctx, while the root key (held by
        the cap) is untouched.

        This is the BACAP primitive behind the Contact Voucher's VoucherSalt:
        the joiner mutates their WriteCap and the inductor mutates the paired
        ReadCap by the same ctx, so writer and readers land on the same
        mutated sequence.
        """
        okm = _hkdf_blake2b(
            secret=self.hkdf_state,
            salt=ctx,
            info=_MUTATE_KDF_STATE_LABEL,
            length=96,
        )
        return MessageBoxIndex(self.idx_64, okm[64:96], okm[32:64], okm[:32])

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


    def open_for_context(
        self,
        read_cap: "ReadCap",
        ctx: bytes,
        box: bytes,
        ciphertext: bytes,
        signature: bytes,
    ) -> bytes:
        """Verifies and decrypts the box at this index on read_cap's stream.

        Unlike decrypt_for_context, it first checks that box is the one
        read_cap and this index derive under ctx. That matters most for
        tombstones: a tombstone has no ciphertext to authenticate, so
        decrypt_for_context alone accepts a tombstone signed for any box.
        """
        if len(box) != BoxIDSize:
            raise InvalidArgument("invalid box length")
        if not any(box):
            raise EmptyBox("empty box, no message received")
        if not hmac.compare_digest(box, self.box_id_for_context(read_cap, ctx)):
            raise BoxIDMismatch("box is not the one the capability and index derive")
        return self.decrypt_for_context(box, ctx, ciphertext, signature)


# contains walks at most this many ratchet steps: a few microseconds each in
# Go, far more boxes than a stream holds between rewrites, and a cap on what a
# hostile index can cost. The same bound as Go's.
MAX_CONTAINS_WALK = 1 << 18


def _contains(start: MessageBoxIndex, idx: MessageBoxIndex) -> None:
    if idx is None:
        raise InvalidArgument("nil index")
    if idx.idx_64 < start.idx_64:
        raise IndexNotInChannel("index is not on this capability's stream")
    if idx.idx_64 - start.idx_64 > MAX_CONTAINS_WALK:
        raise IndexTooFar("index is too far ahead to check")
    if not hmac.compare_digest(start.advance_index_to(idx.idx_64).to_bytes(), idx.to_bytes()):
        raise IndexNotInChannel("index is not on this capability's stream")


def _seed_from_signing_key(sk: BlindableSigningKey) -> bytes:
    """Returns the 32-byte ed25519 seed from a SigningKey."""
    return bytes(sk)


def _ed25519_64byte_private(sk: BlindableSigningKey) -> bytes:
    """Returns the 64-byte (seed||pubkey) form of an ed25519 private key.

    Matches Go's crypto/ed25519 marshaling so that WriteCap.to_bytes()
    is byte-identical to the Go side's WriteCap.MarshalBinary().
    """
    return _seed_from_signing_key(sk) + bytes(sk.verify_key)


_P = 2**255 - 19
_D = (-121665 * pow(121666, _P - 2, _P)) % _P


def _is_curve_point(encoding: bytes) -> bool:
    """Whether a 32-byte encoding decodes to a point on edwards25519.

    Accepts exactly what Go's filippo.io/edwards25519 Point.SetBytes accepts:
    the sign bit is ignored for the check, and y may be unreduced. A point
    exists for y when x^2 = (y^2 - 1) / (d*y^2 + 1) has a square root.
    """
    y = int.from_bytes(encoding, "little") & ((1 << 255) - 1)
    y2 = y * y % _P
    x2 = (y2 - 1) * pow(_D * y2 + 1, _P - 2, _P) % _P
    return x2 == 0 or pow(x2, (_P - 1) // 2, _P) == 1


@dataclasses.dataclass(frozen=True)
class WriteCap:
    """Holds the root private key plus the conversation's first MessageBoxIndex.

    The bearer of a WriteCap can derive the full box ID sequence and the
    corresponding signing keys; deriving a ReadCap from it gives someone
    else the ability to read but not write.
    """

    root_private_key: BlindableSigningKey
    message_box_index: MessageBoxIndex

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
        return _ed25519_64byte_private(self.root_private_key) + self.message_box_index.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "WriteCap":
        if len(data) != WriteCapSize:
            raise InvalidArgument("invalid WriteCap binary size")
        # Go stores seed||pubkey. The stored public key must be the one the
        # seed derives, as Go requires: a cap whose halves disagree would
        # derive box IDs from one key and sign with another.
        sk = BlindableSigningKey(data[:32])
        if bytes(sk.verify_key) != data[32:_Ed25519PrivateKeySize]:
            raise InvalidArgument("WriteCap public key does not match its seed")
        idx = MessageBoxIndex.from_bytes(data[_Ed25519PrivateKeySize:])
        return cls(sk, idx)

    def read_cap(self) -> "ReadCap":
        """Returns the ReadCap derived from this WriteCap."""
        return ReadCap(self.root_public_key, self.message_box_index)

    def mutate_kdf_state(self, ctx: bytes) -> "WriteCap":
        """Returns a new WriteCap with its first index re-seeded by ctx.

        See MessageBoxIndex.mutate_kdf_state. The root key is shared; applying
        this with the same ctx as ReadCap.mutate_kdf_state on the paired read
        cap keeps writer and readers in lockstep.
        """
        return WriteCap(
            self.root_private_key,
            self.message_box_index.mutate_kdf_state(ctx),
        )

    def with_message_box_index(self, idx: MessageBoxIndex) -> "WriteCap":
        """Returns a copy of this WriteCap re-based to idx, leaving self unchanged.

        Re-basing a cap to a chosen position (e.g. the live edge) before handing
        it out means the recipient learns nothing about indices before idx.
        """
        if idx is None:
            raise InvalidArgument("with_message_box_index: nil index")
        return WriteCap(self.root_private_key, idx)

    def derive_box_id(self, message_box_index: MessageBoxIndex) -> bytes:
        return message_box_index.derive_message_box_id(self.root_public_key)

    def contains(self, idx: MessageBoxIndex) -> None:
        """Raises unless idx lies on this cap's stream. See ReadCap.contains."""
        _contains(self.message_box_index, idx)

    def start(self) -> "WritePosition":
        """The position of the cap's own index: the first box it writes."""
        from .positions import WritePosition
        return WritePosition._make(self, self.message_box_index)

    def position_at(self, idx: MessageBoxIndex) -> "WritePosition":
        """The position of idx on this cap's stream, after checking it is on it."""
        from .positions import WritePosition
        self.contains(idx)
        return WritePosition._make(self, idx)


@dataclasses.dataclass(frozen=True)
class ReadCap:
    """Holds the root public key plus the conversation's first MessageBoxIndex.

    The bearer can derive the full box-ID sequence and verify+decrypt
    messages, but cannot sign new ones.
    """

    root_public_key: BlindableVerifyKey
    message_box_index: MessageBoxIndex

    def to_bytes(self) -> bytes:
        return bytes(self.root_public_key) + self.message_box_index.to_bytes()

    @classmethod
    def from_bytes(cls, data: bytes) -> "ReadCap":
        if len(data) != ReadCapSize:
            raise InvalidArgument("invalid ReadCap binary size")
        if not _is_curve_point(data[:BoxIDSize]):
            raise InvalidArgument("ReadCap root public key is not a curve point")
        pk = BlindableVerifyKey(data[:BoxIDSize])
        idx = MessageBoxIndex.from_bytes(data[BoxIDSize:])
        return cls(pk, idx)

    def derive_box_id(self, message_box_index: MessageBoxIndex) -> bytes:
        return message_box_index.derive_message_box_id(self.root_public_key)

    def mutate_kdf_state(self, ctx: bytes) -> "ReadCap":
        """Returns a new ReadCap with its first index re-seeded by ctx.

        See MessageBoxIndex.mutate_kdf_state. Matches WriteCap.mutate_kdf_state
        applied to the paired write cap with the same ctx.
        """
        return ReadCap(
            self.root_public_key,
            self.message_box_index.mutate_kdf_state(ctx),
        )

    def with_message_box_index(self, idx: MessageBoxIndex) -> "ReadCap":
        """Returns a copy of this ReadCap re-based to idx, leaving self unchanged.

        Re-basing to the current position before sharing means the recipient
        starts there and cannot iterate the one-way ratchet back to count
        earlier messages.
        """
        if idx is None:
            raise InvalidArgument("with_message_box_index: nil index")
        return ReadCap(self.root_public_key, idx)

    def contains(self, idx: MessageBoxIndex) -> None:
        """Raises unless idx lies on this cap's stream.

        Steps the cap's own index forward to idx. Raises IndexNotInChannel if
        idx is not on the stream (another stream's, one re-seeded by
        mutate_kdf_state, or one behind the cap's own index), and IndexTooFar
        if it lies further ahead than MAX_CONTAINS_WALK steps.
        """
        _contains(self.message_box_index, idx)

    def start(self) -> "ReadPosition":
        """The position of the cap's own index: the first box its holder can read."""
        from .positions import ReadPosition
        return ReadPosition._make(self, self.message_box_index)

    def position_at(self, idx: MessageBoxIndex) -> "ReadPosition":
        """The position of idx on this cap's stream, after checking it is on it."""
        from .positions import ReadPosition
        self.contains(idx)
        return ReadPosition._make(self, idx)
