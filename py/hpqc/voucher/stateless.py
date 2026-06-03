# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Stateless Contact Voucher primitives.

Pure functions, no IO. Every operation takes bytes or caps and returns
bytes or values; the caller performs all pigeonhole reads, writes, the
COPY all-or-nothing, and the box-0 tombstone. See the protocol narration
at ``website/content/en/docs/specs/contact_voucher_narration.md``.

The two streams and the seal keypair:

  - **MessageStream** is an ordinary BACAP stream; the joiner keeps its
    WriteCap and the ReadCap travels inside the SignedPleaseAdd.
  - **VoucherKeypair** is the seal keypair, a hybrid post-quantum NIKE
    keypair (CTIDH1024-X25519). The inductor seals the reply to its
    public key; only the joiner, holding the secret key, can open it.
  - **VoucherStream** is the rendezvous BACAP stream, derived
    deterministically from the Voucher hash so both parties reproduce
    it. Box 0 holds the VoucherPayload, box 1 the sealed reply.
"""
from __future__ import annotations

import dataclasses
import hashlib
import os
from typing import Callable, Optional, Tuple

from cryptography.exceptions import InvalidTag

from hpqc.hash import sum256
from hpqc.kem.mkem import MKEMScheme
from hpqc.nike.ctidh1024 import CTIDH1024
from hpqc.nike.hybrid import HybridNIKE
from hpqc.nike.x25519 import X25519
from hpqc.sign.ed25519 import Ed25519Scheme

from hpqc.bacap import ReadCap, WriteCap

from .exceptions import (
    InvalidArgument,
    SealOpenFailed,
    SignatureVerificationFailed,
    VoucherHashMismatch,
)
from .messages import (
    PleaseAdd,
    SignedPleaseAdd,
    VoucherPayload,
    VoucherReply,
)

#: The VoucherKeypair seal: MKEM over the same hybrid PQ NIKE the pigeonhole
#: couriers use (CTIDH1024-X25519). Lowest bandwidth of the PQ options and
#: maximal reuse. All reply keys must come from this one scheme instance,
#: since MKEM's NIKE checks key/scheme identity. The component order is
#: X25519 first, then CTIDH1024, matching Go's schemes.ByName(
#: "CTIDH1024-X25519") (hybrid.CTIDH1024X25519) and the storage replicas,
#: so the reply key bytes and seal ciphertext are byte-identical across the
#: Python and Go implementations.
SEAL_NIKE = HybridNIKE(X25519(), CTIDH1024(), name="CTIDH1024-X25519")
SEAL_MKEM = MKEMScheme(SEAL_NIKE)

#: Size of a VoucherSalt, which re-seeds the joiner's MessageStream KDF ratchet.
VOUCHER_SALT_SIZE: int = 32


@dataclasses.dataclass(frozen=True)
class ParsedPayload:
    """The verified contents of a VoucherPayload."""

    display_name: str
    message_read_cap: ReadCap
    voucher_pub_key: bytes
    signed_please_add: bytes  # CBOR SignedPleaseAdd, for the group Introduction


def new_salt() -> bytes:
    """Returns a fresh random VoucherSalt."""
    return os.urandom(VOUCHER_SALT_SIZE)


def shake_reader(seed: bytes) -> Callable[[int], bytes]:
    """A deterministic byte source: the SHAKE256 squeeze of ``seed``.

    Returns a ``read(n)`` callable yielding successive bytes of
    ``SHAKE256(seed)``. Go obtains the same stream from
    ``sha3.NewSHAKE256()`` fed ``seed``, so feeding this to
    ``generate_keypair_from_entropy`` or to ``MKEMScheme.encapsulate``
    reproduces the same keys and ciphertext across the two languages.
    """
    state = {"buf": b"", "pos": 0}

    def read(n: int) -> bytes:
        need = state["pos"] + n
        if need > len(state["buf"]):
            # SHAKE256 is an XOF: digest(m)[:k] == digest(k), so squeezing a
            # larger prefix only extends the stream already handed out.
            state["buf"] = hashlib.shake_256(seed).digest(
                max(need, len(state["buf"]) * 2, 4096)
            )
        out = state["buf"][state["pos"]:need]
        state["pos"] = need
        return out

    return read


# ----- VoucherKeypair seal keypair -----

def new_voucher_keypair(seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Generates a VoucherKeypair. Returns (secret_bytes, public_bytes).

    With ``seed`` the keypair is derived deterministically from
    ``SHAKE256(seed)`` (for the cross-language vectors); without it the
    keypair is random.
    """
    if seed is None:
        pub, priv = SEAL_NIKE.generate_keypair()
    else:
        pub, priv = SEAL_NIKE.generate_keypair_from_entropy(shake_reader(seed))
    return priv.to_bytes(), pub.to_bytes()


# ----- SignedPleaseAdd -----

def make_signed_please_add(
    message_write_cap: WriteCap, display_name: str
) -> SignedPleaseAdd:
    """Builds a SignedPleaseAdd, signed by the MessageStream root key.

    The signature is a plain Ed25519 signature over the CBOR PleaseAdd,
    verifiable against the root public key embedded in the read cap.
    """
    if not isinstance(display_name, str):
        raise InvalidArgument("display_name must be a string")
    read_cap = message_write_cap.read_cap()
    please_add_bytes = PleaseAdd(display_name, read_cap).to_bytes()
    signature = bytes(message_write_cap.root_private_key.sign(please_add_bytes).signature)
    return SignedPleaseAdd(please_add_bytes, signature)


def verify_signed_please_add(spa: SignedPleaseAdd) -> PleaseAdd:
    """Verifies the SignedPleaseAdd signature; returns the parsed PleaseAdd.

    Raises ``SignatureVerificationFailed`` if the signature does not verify
    under the root public key embedded in the read cap.
    """
    please_add = spa.parsed()
    pubkey = bytes(please_add.message_read_cap.root_public_key)
    if not Ed25519Scheme.verify(pubkey, spa.please_add, spa.signature):
        raise SignatureVerificationFailed(
            "SignedPleaseAdd did not verify under its read cap's root public key"
        )
    return please_add


# ----- VoucherPayload and the Voucher hash -----

def assemble_voucher_payload(
    signed_please_add: SignedPleaseAdd, voucher_pub_key: bytes
) -> Tuple[bytes, bytes]:
    """Assembles the VoucherPayload. Returns (voucher_hash, payload_bytes)."""
    payload_bytes = VoucherPayload(
        signed_please_add.to_bytes(), bytes(voucher_pub_key)
    ).to_bytes()
    return sum256(payload_bytes), payload_bytes


def parse_and_verify_payload(voucher: bytes, payload_bytes: bytes) -> ParsedPayload:
    """Checks the payload hashes to the Voucher, then verifies the signature."""
    if len(voucher) != 32:
        raise InvalidArgument("voucher must be 32 bytes")
    if sum256(payload_bytes) != bytes(voucher):
        raise VoucherHashMismatch("VoucherPayload does not hash to the Voucher")
    payload = VoucherPayload.from_bytes(payload_bytes)
    spa = SignedPleaseAdd.from_bytes(payload.signed_please_add)
    please_add = verify_signed_please_add(spa)
    return ParsedPayload(
        display_name=please_add.display_name,
        message_read_cap=please_add.message_read_cap,
        voucher_pub_key=payload.voucher_pub_key,
        signed_please_add=payload.signed_please_add,
    )


# ----- VoucherStream derivation (deterministic from the Voucher) -----

def derive_voucher_stream(voucher: bytes) -> Tuple[WriteCap, ReadCap]:
    """Deterministically derives the VoucherStream WriteCap and ReadCap.

    The 32-byte Voucher seeds a SHAKE256 stream that drives BACAP key
    generation, consuming the ed25519 seed (32), the HKDF state (32), and
    the start-index bytes (16) in that order. Go reproduces the same caps
    by feeding ``bacap.NewWriteCap`` the same ``sha3.NewSHAKE256(voucher)``
    stream.
    """
    if len(voucher) != 32:
        raise InvalidArgument("voucher must be 32 bytes")
    write_cap = WriteCap.generate(shake_reader(bytes(voucher)))
    return write_cap, write_cap.read_cap()


# ----- the seal -----

def seal_reply(
    voucher_pub_key: bytes,
    who_reply: bytes,
    salt: bytes,
    seal_seed: Optional[bytes] = None,
) -> bytes:
    """Seals (who_reply, salt) to the VoucherKeypair public key. Returns ciphertext bytes.

    With ``seal_seed`` the MKEM ephemeral key and nonces are drawn from
    ``SHAKE256(seal_seed)``, so the sealed bytes are reproducible (for the
    cross-language vectors); without it they are random.
    """
    if len(salt) != VOUCHER_SALT_SIZE:
        raise InvalidArgument(f"salt must be {VOUCHER_SALT_SIZE} bytes")
    voucher_pub = SEAL_NIKE.public_key_from_bytes(bytes(voucher_pub_key))
    plaintext = VoucherReply(bytes(who_reply), bytes(salt)).to_bytes()
    entropy = shake_reader(seal_seed) if seal_seed is not None else None
    _ephemeral_priv, ciphertext = SEAL_MKEM.encapsulate(
        [voucher_pub], plaintext, entropy=entropy
    )
    return ciphertext.marshal()


def open_sealed_reply(voucher_secret_key: bytes, sealed: bytes) -> VoucherReply:
    """Opens a sealed reply with the VoucherKeypair secret key.

    Raises ``SealOpenFailed`` if the ciphertext does not authenticate under
    this key or the recovered plaintext is malformed.
    """
    voucher_priv = SEAL_NIKE.private_key_from_bytes(bytes(voucher_secret_key))
    try:
        ciphertext = SEAL_MKEM.ciphertext_from_bytes(bytes(sealed))
        plaintext = SEAL_MKEM.decapsulate(voucher_priv, ciphertext)
    except (ValueError, InvalidTag) as e:
        raise SealOpenFailed("could not open sealed reply") from e
    try:
        return VoucherReply.from_bytes(plaintext)
    except InvalidArgument as e:
        raise SealOpenFailed("sealed reply plaintext was malformed") from e
