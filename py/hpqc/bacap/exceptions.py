# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Exception hierarchy for the BACAP API.

All exceptions raised from ``hpqc.bacap`` derive from ``BACAPError``,
so callers can catch the entire surface with a single ``except``. The
distinct subclasses let a caller act on the specific failure mode:

  - ``InvalidArgument``: caller-supplied input is malformed (wrong
    size, wrong type, out of range, ``None`` where required, or the
    object is in a state that does not permit the requested operation).
    A bug on the caller's side.

  - ``CannotRewind``: caller tried to advance a ``MessageBoxIndex`` to
    an earlier position. Specific subclass of ``InvalidArgument``
    because rewind is a recurring, recognisable misuse worth catching
    on its own.

  - ``EmptyBox``: a stateful reader was handed a zero-byte box ID,
    indicating no message has been deposited at that index yet.
    Typically a transient condition rather than a protocol violation.

  - ``BoxIDMismatch``: the box ID supplied to a stateful reader does
    not match the box ID it expected next. The caller may have read
    out of order, or the message may belong to a different
    conversation.

  - ``SignatureVerificationFailed``: a BACAP signature did not verify
    under the expected box-ID public key. Always a protocol failure
    or tampering.

  - ``DecryptionFailed``: AES-256-GCM-SIV authentication failed at
    decryption time. Always a protocol failure or tampering.
"""
from __future__ import annotations


class BACAPError(Exception):
    """Base class for all BACAP-specific exceptions."""


class InvalidArgument(BACAPError):
    """Caller supplied invalid input (wrong size/type, None, bad state)."""


class CannotRewind(InvalidArgument):
    """Attempted to advance a MessageBoxIndex to an earlier position."""


class EmptyBox(BACAPError):
    """Box ID is all-zero; no message available at this index."""


class BoxIDMismatch(BACAPError):
    """Received box ID does not match the expected box ID."""


class SignatureVerificationFailed(BACAPError):
    """Signature did not verify under the expected box-ID public key."""


class DecryptionFailed(BACAPError):
    """AES-256-GCM-SIV authentication failed at decryption time."""
