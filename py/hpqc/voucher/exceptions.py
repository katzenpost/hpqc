# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Exception hierarchy for the Contact Voucher API.

All exceptions raised from ``hpqc.voucher`` derive from ``VoucherError``,
so a caller can catch the whole surface with one ``except``. The
subclasses let a caller act on the specific failure mode:

  - ``InvalidArgument``: caller-supplied input is malformed (wrong size
    or type, ``None`` where required, out of range). A bug on the
    caller's side.

  - ``VoucherHashMismatch``: a fetched VoucherPayload does not hash to
    the Voucher the reader holds. The payload was tampered with, or the
    wrong box was read.

  - ``SignatureVerificationFailed``: the SignedPleaseAdd did not verify
    under the root public key embedded in its read cap. Tampering or a
    forged membership claim.

  - ``SealOpenFailed``: the sealed reply could not be opened, either
    because the MKEM authentication failed or the recovered plaintext
    was malformed. Wrong key, corruption, or tampering.

  - ``BoxIDMismatch``: a box ID handed to a reader does not match the
    box ID expected at that index of the VoucherStream.
"""
from __future__ import annotations


class VoucherError(Exception):
    """Base class for all Contact Voucher exceptions."""


class InvalidArgument(VoucherError):
    """Caller supplied invalid input (wrong size/type, None, out of range)."""


class VoucherHashMismatch(VoucherError):
    """VoucherPayload does not hash to the expected Voucher."""


class SignatureVerificationFailed(VoucherError):
    """SignedPleaseAdd did not verify under its read cap's root public key."""


class SealOpenFailed(VoucherError):
    """The sealed reply could not be opened (bad key, corruption, tampering)."""


class BoxIDMismatch(VoucherError):
    """A supplied box ID does not match the expected VoucherStream box ID."""
