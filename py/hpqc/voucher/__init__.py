# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Contact Voucher protocol cryptography.

The Contact Voucher lets a newcomer (the joiner) hand an existing group
member (the inductor) a single small ``Voucher`` out of band, after which
the two exchange read capabilities through a hash-derived rendezvous
stream. See ``website/content/en/docs/specs/contact_voucher_narration.md``.

The public surface is four pure methods (no IO): :func:`voucher_mint`,
:func:`voucher_induct`, :func:`voucher_open_reply`, and
:func:`derive_voucher_stream`. The caller performs all pigeonhole reads and
writes, the all-or-nothing COPY, and the box-0 tombstone using the caps and
payloads they return. The Go package ``hpqc/voucher`` exposes the same four
methods and agrees with this one byte-for-byte under shared test vectors.
"""
from .api import (
    InductResult,
    MintResult,
    OpenReplyResult,
    VoucherStream,
    derive_voucher_stream,
    voucher_induct,
    voucher_mint,
    voucher_open_reply,
)
from .exceptions import (
    InvalidArgument,
    SealOpenFailed,
    SignatureVerificationFailed,
    VoucherError,
    VoucherHashMismatch,
)
from .messages import (
    PleaseAdd,
    SignedPleaseAdd,
    VoucherPayload,
    VoucherReply,
)
from .stateless import VOUCHER_SALT_SIZE

__all__ = [
    # the four methods
    "voucher_mint",
    "voucher_induct",
    "voucher_open_reply",
    "derive_voucher_stream",
    # result types
    "MintResult",
    "InductResult",
    "OpenReplyResult",
    "VoucherStream",
    # message types
    "PleaseAdd",
    "SignedPleaseAdd",
    "VoucherPayload",
    "VoucherReply",
    # exceptions
    "VoucherError",
    "InvalidArgument",
    "VoucherHashMismatch",
    "SignatureVerificationFailed",
    "SealOpenFailed",
    # constants
    "VOUCHER_SALT_SIZE",
]
