# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Round-trip self-tests for the Python BACAP port.

These exercise the stateless and stateful APIs end-to-end on
freshly-generated keys: encrypt with one side, decrypt with the
other, and confirm box IDs / signatures / plaintexts agree. They do
not yet cross-check against Go-generated test vectors; that comes in
a separate vector-driven test once the Go generator emits BACAP
vectors into testvectors/bacap/.
"""
from __future__ import annotations

import pytest

from hpqc.bacap import (
    BACAPError,
    BoxIDMismatch,
    BoxIDSize,
    CannotRewind,
    DecryptionFailed,
    EmptyBox,
    InvalidArgument,
    MessageBoxIndex,
    MessageBoxIndexSize,
    ReadCap,
    ReadCapSize,
    SignatureSize,
    SignatureVerificationFailed,
    StatefulReader,
    StatefulWriter,
    WriteCap,
    WriteCapSize,
)


CTX = b"hpqc-bacap-roundtrip-test"


# ----- MessageBoxIndex -----


def test_message_box_index_marshal_round_trip() -> None:
    idx = MessageBoxIndex.random()
    blob = idx.to_bytes()
    assert len(blob) == MessageBoxIndexSize
    assert MessageBoxIndex.from_bytes(blob) == idx


def test_message_box_index_advance_is_idempotent_at_target() -> None:
    idx = MessageBoxIndex.random()
    assert idx.advance_index_to(idx.idx_64) is idx


def test_message_box_index_cannot_rewind() -> None:
    idx = MessageBoxIndex.random()
    with pytest.raises(CannotRewind):
        idx.advance_index_to(idx.idx_64 - 1 if idx.idx_64 > 0 else 0)


def test_message_box_index_advance_then_rederive() -> None:
    idx = MessageBoxIndex.random()
    a = idx.advance_index_to(idx.idx_64 + 5)
    b = idx.advance_index_to(idx.idx_64 + 5)
    assert a == b
    # Stepping one at a time arrives at the same place.
    c = idx
    for _ in range(5):
        c = c.next_index()
    assert c == a


# ----- WriteCap / ReadCap -----


def test_writecap_marshal_round_trip() -> None:
    wc = WriteCap.generate()
    blob = wc.to_bytes()
    assert len(blob) == WriteCapSize
    wc2 = WriteCap.from_bytes(blob)
    assert wc.to_bytes() == wc2.to_bytes()
    # The re-derived pubkey must match the original.
    assert bytes(wc.root_public_key) == bytes(wc2.root_public_key)


def test_readcap_marshal_round_trip() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()
    blob = rc.to_bytes()
    assert len(blob) == ReadCapSize
    rc2 = ReadCap.from_bytes(blob)
    assert rc.to_bytes() == rc2.to_bytes()


def test_writecap_and_readcap_share_box_ids() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()
    idx = wc.first_message_box_index
    assert wc.derive_box_id(idx) == rc.derive_box_id(idx)


# ----- encrypt / decrypt round trip -----


def test_encrypt_then_decrypt_for_context() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()
    idx = wc.first_message_box_index
    plaintext = b"the eagle has landed"

    box_id, ciphertext, sig = idx.encrypt_for_context(wc, CTX, plaintext)
    assert len(box_id) == BoxIDSize
    assert len(sig) == SignatureSize

    # The receiver derives the same expected box ID from its ReadCap.
    assert idx.box_id_for_context(rc, CTX) == box_id

    # Decrypt with the same index + ctx; signature must verify and
    # plaintext must round-trip.
    recovered = idx.decrypt_for_context(box_id, CTX, ciphertext, sig)
    assert recovered == plaintext


def test_decrypt_rejects_bad_signature() -> None:
    wc = WriteCap.generate()
    idx = wc.first_message_box_index
    box_id, ciphertext, sig = idx.encrypt_for_context(wc, CTX, b"hello")
    # Flip a bit in the signature.
    bad = bytearray(sig)
    bad[0] ^= 0x01
    with pytest.raises(SignatureVerificationFailed):
        idx.decrypt_for_context(box_id, CTX, ciphertext, bytes(bad))


def test_tombstone_decrypt_returns_empty() -> None:
    """A signed empty ciphertext is treated as a tombstone."""
    wc = WriteCap.generate()
    idx = wc.first_message_box_index
    # Sign an empty payload at this index/ctx.
    box_id, sig = idx.sign_box(wc, CTX, b"")
    plaintext = idx.decrypt_for_context(box_id, CTX, b"", sig)
    assert plaintext == b""


# ----- StatefulWriter / StatefulReader -----


def test_stateful_writer_then_reader_three_messages() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()
    writer = StatefulWriter(wc, CTX)
    reader = StatefulReader(rc, CTX)

    messages = [b"first", b"second", b"third"]
    sent = []
    for m in messages:
        box_id, ciphertext, sig = writer.encrypt_next(m)
        sent.append((box_id, ciphertext, sig))

    for (box_id, ciphertext, sig), expected in zip(sent, messages):
        # The reader's view of the next box ID must match the writer's.
        assert reader.next_box_id() == box_id
        plaintext = reader.decrypt_next(CTX, box_id, ciphertext, sig)
        assert plaintext == expected


def test_stateful_writer_prepare_then_advance() -> None:
    wc = WriteCap.generate()
    writer = StatefulWriter(wc, CTX)
    initial_idx = writer.get_current_message_index()

    box_id, ciphertext, sig = writer.prepare_next(b"deferred")
    # State has not advanced.
    assert writer.get_current_message_index() == initial_idx

    writer.advance_state()
    assert writer.get_current_message_index() != initial_idx


def test_stateful_reader_rejects_wrong_box_id() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()
    writer = StatefulWriter(wc, CTX)
    reader = StatefulReader(rc, CTX)

    box_id, ciphertext, sig = writer.encrypt_next(b"hi")
    # Tamper with the box ID.
    bad_box = bytes(b ^ 0x01 for b in box_id)
    with pytest.raises(BoxIDMismatch):
        reader.decrypt_next(CTX, bad_box, ciphertext, sig)


def test_stateful_reader_rejects_zero_box() -> None:
    wc = WriteCap.generate()
    rc = wc.read_cap()
    reader = StatefulReader(rc, CTX)
    with pytest.raises(EmptyBox):
        reader.decrypt_next(CTX, b"\x00" * BoxIDSize, b"x", b"\x00" * SignatureSize)


def test_stateful_reader_with_explicit_index() -> None:
    """Resuming a reader from a known checkpoint mid-conversation."""
    wc = WriteCap.generate()
    rc = wc.read_cap()
    writer = StatefulWriter(wc, CTX)

    # Advance to the third message.
    writer.encrypt_next(b"a")
    writer.encrypt_next(b"b")
    box_id_c, ct_c, sig_c = writer.encrypt_next(b"c")

    # A fresh reader resumed at the third index should accept it.
    third_idx = rc.first_message_box_index.advance_index_to(
        rc.first_message_box_index.idx_64 + 2
    )
    reader = StatefulReader(rc, CTX, next_index=third_idx)
    plaintext = reader.decrypt_next(CTX, box_id_c, ct_c, sig_c)
    assert plaintext == b"c"
    # last_inbox_read is None on resume; advanced after the read.
    assert reader.last_inbox_read == third_idx


# ----- the two APIs agree byte-for-byte -----


def test_stateful_and_stateless_agree() -> None:
    wc = WriteCap.generate()
    writer = StatefulWriter(wc, CTX)

    plaintext = b"compatible"

    # Path A: stateless encrypt at the writer's current index.
    cur = writer.get_current_message_index()
    box_id_a, ct_a, sig_a = cur.encrypt_for_context(wc, CTX, plaintext)

    # Path B: stateful encrypt_next.
    box_id_b, ct_b, sig_b = writer.encrypt_next(plaintext)

    assert box_id_a == box_id_b
    assert ct_a == ct_b
    assert sig_a == sig_b


# ----- exception hierarchy -----


def test_invalid_argument_on_wrong_size_bytes() -> None:
    with pytest.raises(InvalidArgument):
        MessageBoxIndex.from_bytes(b"\x00" * (MessageBoxIndexSize - 1))
    with pytest.raises(InvalidArgument):
        WriteCap.from_bytes(b"\x00" * (WriteCapSize - 1))
    with pytest.raises(InvalidArgument):
        ReadCap.from_bytes(b"\x00" * (ReadCapSize - 1))


def test_decryption_failed_on_corrupt_ciphertext() -> None:
    wc = WriteCap.generate()
    idx = wc.first_message_box_index
    box_id, ciphertext, sig = idx.encrypt_for_context(wc, CTX, b"hello")

    # Flip a bit in the middle of the ciphertext (signature still verifies
    # over the *altered* bytes only if we re-sign, so for this test we
    # alter the ciphertext and re-sign with the blinded private key so we
    # reach the AES-GCM-SIV stage instead of failing at the signature.
    bad_ct = bytearray(ciphertext)
    bad_ct[len(bad_ct) // 2] ^= 0x01
    # Re-derive the blinded signing key and produce a valid signature
    # over the corrupted ciphertext.
    from hpqc.bacap.stateless import _hkdf_blake2b
    k_ctx = _hkdf_blake2b(idx.cur_blinding_factor, CTX, b"", 32)
    bad_sig = wc.root_private_key.blind(k_ctx).sign(bytes(bad_ct))[:64]

    with pytest.raises(DecryptionFailed):
        idx.decrypt_for_context(box_id, CTX, bytes(bad_ct), bad_sig)


def test_all_bacap_errors_inherit_from_BACAPError() -> None:
    """Catching BACAPError must catch every BACAP-specific exception."""
    # Construct the simplest case for each subclass and confirm the catch.
    wc = WriteCap.generate()
    rc = wc.read_cap()
    idx = wc.first_message_box_index

    # InvalidArgument
    with pytest.raises(BACAPError):
        MessageBoxIndex.from_bytes(b"")
    # CannotRewind also inherits InvalidArgument; both should be caught
    # as BACAPError.
    with pytest.raises(BACAPError):
        idx.advance_index_to(0) if idx.idx_64 == 0 else idx.advance_index_to(idx.idx_64 - 1)
    # SignatureVerificationFailed
    box_id, ciphertext, sig = idx.encrypt_for_context(wc, CTX, b"x")
    bad_sig = bytes([sig[0] ^ 1]) + sig[1:]
    with pytest.raises(BACAPError):
        idx.decrypt_for_context(box_id, CTX, ciphertext, bad_sig)
    # EmptyBox
    reader = StatefulReader(rc, CTX)
    with pytest.raises(BACAPError):
        reader.decrypt_next(CTX, b"\x00" * BoxIDSize, b"x", b"\x00" * SignatureSize)
    # BoxIDMismatch
    box_id2, ct2, sig2 = idx.encrypt_for_context(wc, CTX, b"y")
    bad_box = bytes(b ^ 1 for b in box_id2)
    reader2 = StatefulReader(rc, CTX)
    with pytest.raises(BACAPError):
        reader2.decrypt_next(CTX, bad_box, ct2, sig2)


def test_cannot_rewind_is_a_subclass_of_invalid_argument() -> None:
    """Catching InvalidArgument must also catch CannotRewind."""
    idx = MessageBoxIndex.random()
    if idx.idx_64 == 0:
        pytest.skip("rare case: random index landed at 0; nothing to rewind to")
    with pytest.raises(InvalidArgument):
        idx.advance_index_to(idx.idx_64 - 1)
