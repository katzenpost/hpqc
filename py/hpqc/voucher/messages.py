# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Wire message types for the Contact Voucher protocol.

All structures are immutable values that serialise to canonical CBOR,
mirroring the group-chat spec's choice of CBOR for these envelopes. The
``WhoReply`` and ``Introduction`` contents are deliberately opaque
``bytes`` here: they belong to the group-chat layer, not the voucher.

Layering:

  - ``PleaseAdd`` is the joiner's name-and-readcap claim.
  - ``SignedPleaseAdd`` wraps the CBOR of a ``PleaseAdd`` with a plain
    Ed25519 signature made by the read cap's root signing key.
  - ``VoucherPayload`` is what goes into VoucherStream box 0: the
    ``SignedPleaseAdd`` plus the reply-stream public key.
  - ``VoucherReply`` is the sealed plaintext the inductor returns: the
    opaque WhoReply blob plus the VoucherSalt that becomes the live
    MessageStream context.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Dict

import cbor2

from hpqc.bacap import ReadCap

from .exceptions import InvalidArgument


def _load_map(data: bytes, what: str) -> Dict[Any, Any]:
    try:
        d = cbor2.loads(data)
    except Exception as e:  # noqa: BLE001 - any CBOR error is a caller bug
        raise InvalidArgument(f"{what}: not valid CBOR") from e
    if not isinstance(d, dict):
        raise InvalidArgument(f"{what}: expected a CBOR map")
    return d


def _field(d: Dict[Any, Any], key: str, what: str) -> Any:
    try:
        return d[key]
    except KeyError as e:
        raise InvalidArgument(f"{what}: missing field {key}") from e


@dataclasses.dataclass(frozen=True)
class PleaseAdd:
    """A joiner's request to be added: display name plus MessageStream read cap."""

    display_name: str
    message_read_cap: ReadCap

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "DisplayName": self.display_name,
                "MessageReadCap": self.message_read_cap.to_bytes(),
            },
            canonical=True,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "PleaseAdd":
        d = _load_map(data, "PleaseAdd")
        name = _field(d, "DisplayName", "PleaseAdd")
        read_cap_bytes = _field(d, "MessageReadCap", "PleaseAdd")
        if not isinstance(name, str):
            raise InvalidArgument("PleaseAdd: DisplayName must be a string")
        return cls(name, ReadCap.from_bytes(bytes(read_cap_bytes)))


@dataclasses.dataclass(frozen=True)
class SignedPleaseAdd:
    """A ``PleaseAdd`` (as CBOR) plus an Ed25519 signature over those bytes."""

    please_add: bytes  # CBOR-encoded PleaseAdd
    signature: bytes  # 64-byte plain Ed25519 signature over please_add

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {"PleaseAdd": self.please_add, "Signature": self.signature},
            canonical=True,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "SignedPleaseAdd":
        d = _load_map(data, "SignedPleaseAdd")
        return cls(
            bytes(_field(d, "PleaseAdd", "SignedPleaseAdd")),
            bytes(_field(d, "Signature", "SignedPleaseAdd")),
        )

    def parsed(self) -> PleaseAdd:
        return PleaseAdd.from_bytes(self.please_add)


@dataclasses.dataclass(frozen=True)
class VoucherPayload:
    """VoucherStream box 0 content: the SignedPleaseAdd and the reply pub key."""

    signed_please_add: bytes  # CBOR-encoded SignedPleaseAdd
    reply_pub_key: bytes  # ReplyStream hybrid NIKE public key

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {
                "SignedPleaseAdd": self.signed_please_add,
                "ReplyPubKey": self.reply_pub_key,
            },
            canonical=True,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VoucherPayload":
        d = _load_map(data, "VoucherPayload")
        return cls(
            bytes(_field(d, "SignedPleaseAdd", "VoucherPayload")),
            bytes(_field(d, "ReplyPubKey", "VoucherPayload")),
        )


@dataclasses.dataclass(frozen=True)
class VoucherReply:
    """The sealed reply plaintext: an opaque WhoReply blob plus the salt."""

    who_reply: bytes
    salt: bytes

    def to_bytes(self) -> bytes:
        return cbor2.dumps(
            {"WhoReply": self.who_reply, "VoucherSalt": self.salt},
            canonical=True,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "VoucherReply":
        d = _load_map(data, "VoucherReply")
        return cls(
            bytes(_field(d, "WhoReply", "VoucherReply")),
            bytes(_field(d, "VoucherSalt", "VoucherReply")),
        )
