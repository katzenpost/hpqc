# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The Contact Voucher public API: four pure methods.

Each method is a pure function of bytes and values to bytes and values; no
IO, no clock, no sockets. The caller performs every pigeonhole read and
write, the all-or-nothing COPY, and the box-0 tombstone, using the caps and
payloads these methods return. All key material crosses the boundary as
opaque bytes, so a thin client may hold and persist it without performing
any cryptography itself.

The Go package ``hpqc/voucher`` exposes the same four methods, and the two
agree byte-for-byte under shared test vectors:

  - :func:`voucher_mint` — the joiner mints a Voucher from their own
    MessageStream write cap.
  - :func:`voucher_induct` — an existing member verifies the published
    payload and seals a reply.
  - :func:`voucher_open_reply` — the joiner opens that sealed reply.
  - :func:`derive_voucher_stream` — derive the rendezvous stream caps from
    the Voucher, which the inductor needs to read box 0 before inducting.

Randomness is injectable (``reply_seed``, ``salt``, ``seal_seed``) so every
method is deterministic for the vectors; omit the seeds for production use.
"""
from __future__ import annotations

import dataclasses
from typing import Optional

from hpqc.bacap import WriteCap

from . import stateless


@dataclasses.dataclass(frozen=True)
class MintResult:
    """What :func:`voucher_mint` returns.

    ``voucher`` is the 32-byte token handed to the inductor out of band.
    ``voucher_payload`` is published to VoucherStream box 0. The caller
    persists ``reply_private_key`` to open the reply later, and uses the
    stream caps to publish box 0 and poll box 1.
    """

    voucher: bytes
    voucher_payload: bytes
    voucher_write_cap: bytes
    voucher_read_cap: bytes
    reply_private_key: bytes
    reply_public_key: bytes


@dataclasses.dataclass(frozen=True)
class InductResult:
    """What :func:`voucher_induct` returns.

    ``message_read_cap`` is the joiner's MessageStream read cap, which the
    inductor adds as a peer. ``sealed_reply`` is written to VoucherStream
    box 1; the stream caps let the caller write box 1 and tombstone box 0.
    ``salt`` is the VoucherSalt that becomes the joiner's live MessageStream
    context.
    """

    display_name: str
    message_read_cap: bytes
    sealed_reply: bytes
    voucher_write_cap: bytes
    voucher_read_cap: bytes
    salt: bytes


@dataclasses.dataclass(frozen=True)
class OpenReplyResult:
    """What :func:`voucher_open_reply` returns: the opaque WhoReply blob and
    the VoucherSalt."""

    who_reply: bytes
    salt: bytes


@dataclasses.dataclass(frozen=True)
class VoucherStream:
    """What :func:`derive_voucher_stream` returns: the rendezvous stream caps."""

    voucher_write_cap: bytes
    voucher_read_cap: bytes


def voucher_mint(
    message_write_cap: bytes,
    display_name: str,
    *,
    reply_seed: Optional[bytes] = None,
) -> MintResult:
    """Mints a Voucher from the joiner's MessageStream write cap."""
    write_cap = WriteCap.from_bytes(bytes(message_write_cap))
    reply_private_key, reply_public_key = stateless.new_reply_keypair(seed=reply_seed)
    signed_please_add = stateless.make_signed_please_add(write_cap, display_name)
    voucher, voucher_payload = stateless.assemble_voucher_payload(
        signed_please_add, reply_public_key
    )
    vwrite, vread = stateless.derive_voucher_stream(voucher)
    return MintResult(
        voucher=voucher,
        voucher_payload=voucher_payload,
        voucher_write_cap=vwrite.to_bytes(),
        voucher_read_cap=vread.to_bytes(),
        reply_private_key=reply_private_key,
        reply_public_key=reply_public_key,
    )


def voucher_induct(
    voucher: bytes,
    voucher_payload: bytes,
    who_reply: bytes,
    *,
    salt: Optional[bytes] = None,
    seal_seed: Optional[bytes] = None,
) -> InductResult:
    """Verifies a published VoucherPayload and seals a reply to the joiner.

    Raises :class:`hpqc.voucher.VoucherHashMismatch` if the payload does not
    hash to the Voucher, or :class:`hpqc.voucher.SignatureVerificationFailed`
    if the SignedPleaseAdd does not verify.
    """
    parsed = stateless.parse_and_verify_payload(bytes(voucher), bytes(voucher_payload))
    vwrite, vread = stateless.derive_voucher_stream(bytes(voucher))
    if salt is None:
        salt = stateless.new_salt()
    sealed_reply = stateless.seal_reply(
        parsed.reply_pub_key, bytes(who_reply), salt, seal_seed=seal_seed
    )
    return InductResult(
        display_name=parsed.display_name,
        message_read_cap=parsed.message_read_cap.to_bytes(),
        sealed_reply=sealed_reply,
        voucher_write_cap=vwrite.to_bytes(),
        voucher_read_cap=vread.to_bytes(),
        salt=salt,
    )


def voucher_open_reply(reply_private_key: bytes, sealed_reply: bytes) -> OpenReplyResult:
    """Opens the inductor's sealed reply with the joiner's reply private key.

    Raises :class:`hpqc.voucher.SealOpenFailed` if the ciphertext does not
    authenticate under this key or the recovered plaintext is malformed.
    """
    reply = stateless.open_sealed_reply(bytes(reply_private_key), bytes(sealed_reply))
    return OpenReplyResult(who_reply=reply.who_reply, salt=reply.salt)


def derive_voucher_stream(voucher: bytes) -> VoucherStream:
    """Derives the VoucherStream caps deterministically from the Voucher."""
    vwrite, vread = stateless.derive_voucher_stream(bytes(voucher))
    return VoucherStream(
        voucher_write_cap=vwrite.to_bytes(),
        voucher_read_cap=vread.to_bytes(),
    )
