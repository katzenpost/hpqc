# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The Contact Voucher API: how a newcomer joins a Pigeonhole group.

The joiner mints a Voucher, a 32-byte code it hands to a member out of band. Both sides
derive the same rendezvous BACAP stream from it: the joiner publishes its request in box 0,
and the member answering (the inductor) publishes a sealed reply from box 1 on, carrying the
group's members and a salt that moves the joiner's stream to a fresh position.

Flow::

    joiner:    m = voucher_mint_compact(write_cap, name)
               write m.voucher_payload to box 0 of the stream at m.voucher_write_cap
               hand m.voucher to a member; keep m.voucher_secret_key
    inductor:  s = derive_voucher_stream(voucher); read box 0 with s.voucher_read_cap
               r = voucher_induct(voucher, payload, who_reply)
               write r.sealed_reply from box 1 on (see Forms); give the group
               r.mutated_message_read_cap
    joiner:    read the reply from box 1 on
               o = voucher_open_reply(m.voucher_secret_key, sealed_reply, write_cap)
               write to the group with o.mutated_message_write_cap; read members from o.who_reply

Forms. A Voucher is minted in one of two forms. The compact form
(:func:`voucher_mint_compact`, the default of :func:`voucher_mint`) puts the CBOR array
``[read_cap, voucher_pub_key, display_name, signature]`` in box 0 and gets a single-recipient
sealed box as its reply, written framed over boxes 1, 2, …: pieces of the box size less one
byte, each behind ``C``, the last behind ``F``. The long form (:func:`voucher_mint_long`) puts
the signed CBOR map that older clients read in box 0 and gets the MKEM ciphertext, unframed in
box 1 alone. :func:`voucher_induct` answers in the payload's form, :func:`voucher_open_reply`
opens either, and :func:`hpqc.voucher.payload_version` tells them apart. Framing a compact
reply over boxes is the caller's job; this module only seals and opens.

Both forms are authenticated twice: the Voucher is the BLAKE2b-256 of box 0, so any change is
detected, and the payload is signed by the joiner's stream root key, so the joiner holds the
stream it names.

Every function is pure (no IO, no clock); keys and capabilities cross as opaque bytes. The seed
and salt arguments fix the randomness for test vectors, under which this module and the Go
package ``hpqc/voucher`` produce the same bytes (``voucher/testdata/voucher_vectors.json`` for
the long form, ``voucher_vectors_v2.json`` for the compact form); omit them in production.
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
    persists ``voucher_secret_key`` to open the reply later, and uses the
    stream caps to publish box 0 and poll box 1.
    """

    voucher: bytes
    voucher_payload: bytes
    voucher_write_cap: bytes
    voucher_read_cap: bytes
    voucher_secret_key: bytes
    voucher_public_key: bytes
    version: int = 2


@dataclasses.dataclass(frozen=True)
class InductResult:
    """What :func:`voucher_induct` returns.

    ``mutated_message_read_cap`` is the joiner's MessageStream read cap after
    the VoucherSalt has been applied: the live read cap the inductor hands the
    group. ``sealed_reply`` is written to VoucherStream box 1; the stream caps
    let the caller write box 1 and tombstone box 0. ``salt`` is the VoucherSalt
    the inductor minted.
    """

    display_name: str
    mutated_message_read_cap: bytes
    sealed_reply: bytes
    voucher_write_cap: bytes
    voucher_read_cap: bytes
    salt: bytes
    version: int = 2
    """The payload's form, which the reply answers in: 2 is the compact array form, sealed as
    a sealed box and written framed; 1 is the map form, sealed with the MKEM and written to
    box 1 alone."""


@dataclasses.dataclass(frozen=True)
class OpenReplyResult:
    """What :func:`voucher_open_reply` returns: the opaque WhoReply blob, the
    VoucherSalt, and ``mutated_message_write_cap``, the joiner's MessageStream
    write cap after the salt has been applied (the live write cap to write real
    messages with)."""

    who_reply: bytes
    salt: bytes
    mutated_message_write_cap: bytes


@dataclasses.dataclass(frozen=True)
class VoucherStream:
    """What :func:`derive_voucher_stream` returns: the rendezvous stream caps."""

    voucher_write_cap: bytes
    voucher_read_cap: bytes


def voucher_mint(
    message_write_cap: bytes,
    display_name: str,
    *,
    keypair_seed: Optional[bytes] = None,
    version: int = 2,
) -> MintResult:
    """Mints a Voucher from the joiner's own MessageStream write capability.

    ``version`` 2 (the default) is the compact form, as :func:`voucher_mint_compact`; 1 is the
    long form, as :func:`voucher_mint_long`. ``display_name`` is the name the group will show.
    The result's ``voucher_payload`` goes to box 0 of the stream at ``voucher_write_cap``;
    ``voucher`` is handed to a member; ``voucher_secret_key`` must be kept to open the reply.
    ``keypair_seed`` fixes the seal keypair for test vectors; omit it otherwise.

    Raises ``InvalidArgument`` for a malformed write cap, ``ValueError`` for another version.
    """
    write_cap = WriteCap.from_bytes(bytes(message_write_cap))
    voucher_secret_key, voucher_public_key = stateless.new_voucher_keypair(
        seed=keypair_seed
    )
    if version == 2:
        voucher, voucher_payload = stateless.assemble_voucher_payload_v2(
            write_cap, voucher_public_key, display_name
        )
    elif version == 1:
        signed_please_add = stateless.make_signed_please_add(write_cap, display_name)
        voucher, voucher_payload = stateless.assemble_voucher_payload(
            signed_please_add, voucher_public_key
        )
    else:
        raise ValueError("voucher payload version must be 1 or 2")
    vwrite, vread = stateless.derive_voucher_stream(voucher)
    return MintResult(
        voucher=voucher,
        voucher_payload=voucher_payload,
        voucher_write_cap=vwrite.to_bytes(),
        voucher_read_cap=vread.to_bytes(),
        voucher_secret_key=voucher_secret_key,
        voucher_public_key=voucher_public_key,
        version=version,
    )


def voucher_induct(
    voucher: bytes,
    voucher_payload: bytes,
    who_reply: bytes,
    *,
    salt: Optional[bytes] = None,
    seal_seed: Optional[bytes] = None,
) -> InductResult:
    """Answers a Voucher: checks the published payload and seals a reply to the joiner, in the
    form the payload was minted in.

    ``voucher`` is the code the joiner handed over; ``voucher_payload`` is what box 0 of its
    stream (from :func:`derive_voucher_stream`) holds; ``who_reply`` is the opaque group
    membership to send, the protocol's ReplyWho encoding. The result's ``sealed_reply`` is
    written from box 1 on: framed when ``version`` is 2, unframed in box 1 when it is 1.
    ``mutated_message_read_cap`` is where the group reads the joiner from now on.
    ``salt`` and ``seal_seed`` fix the randomness for test vectors; omit them otherwise.

    Raises :class:`hpqc.voucher.VoucherHashMismatch` if the payload does not
    hash to the Voucher, or :class:`hpqc.voucher.SignatureVerificationFailed`
    if the SignedPleaseAdd does not verify.
    """
    parsed = stateless.parse_and_verify_payload(bytes(voucher), bytes(voucher_payload))
    vwrite, vread = stateless.derive_voucher_stream(bytes(voucher))
    if salt is None:
        salt = stateless.new_salt()
    if parsed.version == 2:
        sealed_reply = stateless.seal_reply_v2(
            parsed.voucher_pub_key, bytes(who_reply), salt, seal_seed=seal_seed
        )
    else:
        sealed_reply = stateless.seal_reply(
            parsed.voucher_pub_key, bytes(who_reply), salt, seal_seed=seal_seed
        )
    # Mutate the joiner's read cap by the salt: the live read cap for the group.
    mutated_read_cap = parsed.message_read_cap.mutate_kdf_state(salt)
    return InductResult(
        display_name=parsed.display_name,
        mutated_message_read_cap=mutated_read_cap.to_bytes(),
        sealed_reply=sealed_reply,
        voucher_write_cap=vwrite.to_bytes(),
        voucher_read_cap=vread.to_bytes(),
        salt=salt,
        version=parsed.version,
    )


def voucher_open_reply(
    voucher_secret_key: bytes, sealed_reply: bytes, message_write_cap: bytes
) -> OpenReplyResult:
    """Opens the reply to a Voucher the caller minted.

    ``voucher_secret_key`` is :attr:`MintResult.voucher_secret_key`; ``sealed_reply`` is the
    reply's bytes, reassembled from boxes 1 on for a compact Voucher or box 1 alone for a long
    one (either is accepted); ``message_write_cap`` is the write cap the Voucher was minted
    from. The result's ``mutated_message_write_cap`` is where the joiner writes to the group
    from now on; ``who_reply`` is the membership the inductor sent.

    Recovers the VoucherSalt and mutates ``message_write_cap`` by it, returning
    the live write cap the joiner writes real messages with.

    Raises :class:`hpqc.voucher.SealOpenFailed` if the ciphertext does not
    authenticate under this key or the recovered plaintext is malformed.
    """
    reply = stateless.open_sealed_reply(bytes(voucher_secret_key), bytes(sealed_reply))
    write_cap = WriteCap.from_bytes(bytes(message_write_cap))
    mutated_write_cap = write_cap.mutate_kdf_state(reply.salt)
    return OpenReplyResult(
        who_reply=reply.who_reply,
        salt=reply.salt,
        mutated_message_write_cap=mutated_write_cap.to_bytes(),
    )


def derive_voucher_stream(voucher: bytes) -> VoucherStream:
    """The rendezvous stream's capabilities, which both sides compute from the Voucher alone:
    the inductor reads box 0 and writes the reply with them, the joiner reads the reply. Box 0
    is the stream's first index; the reply starts at the next. Raises ``InvalidArgument`` unless
    ``voucher`` is 32 bytes."""
    vwrite, vread = stateless.derive_voucher_stream(bytes(voucher))
    return VoucherStream(
        voucher_write_cap=vwrite.to_bytes(),
        voucher_read_cap=vread.to_bytes(),
    )


def voucher_mint_compact(message_write_cap: bytes, display_name: str, *, keypair_seed: Optional[bytes] = None) -> MintResult:
    """Mints a Voucher in the compact form, the one new clients use: box 0 holds the signed
    array ``[read_cap, voucher_pub_key, display_name, signature]``, and the reply will be a
    sealed box framed over boxes 1 on. See :func:`voucher_mint` for the arguments and result."""
    return voucher_mint(message_write_cap, display_name, keypair_seed=keypair_seed, version=2)


def voucher_mint_long(message_write_cap: bytes, display_name: str, *, keypair_seed: Optional[bytes] = None) -> MintResult:
    """Mints a Voucher in the long form, the signed CBOR map that inductors from before the
    compact form read; use it to join a group whose members have not upgraded. The reply will be
    the MKEM ciphertext, unframed in box 1 alone. See :func:`voucher_mint` for the arguments and
    result."""
    return voucher_mint(message_write_cap, display_name, keypair_seed=keypair_seed, version=1)
