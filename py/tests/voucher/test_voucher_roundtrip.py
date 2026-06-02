# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Round-trip, determinism, and negative tests for the four-method
Contact Voucher API. Pure crypto, no IO. CTIDH keygen makes a few slow.
"""
import pytest

from hpqc.bacap import WriteCap

from hpqc import voucher
from hpqc.voucher import (
    SealOpenFailed,
    SignatureVerificationFailed,
    VoucherHashMismatch,
    derive_voucher_stream,
    voucher_induct,
    voucher_mint,
    voucher_open_reply,
)
from hpqc.voucher import stateless
from hpqc.voucher.messages import SignedPleaseAdd

WHO_REPLY = b"opaque-group-membership-readcaps-blob"
SALT = bytes(range(32))
REPLY_SEED = b"reply-seed".ljust(32, b".")
SEAL_SEED = b"seal-seed".ljust(32, b"!")


def test_full_handshake_roundtrip():
    bob = WriteCap.generate()

    mint = voucher_mint(bob.to_bytes(), "bob")

    # Alice derives the same VoucherStream from the Voucher alone.
    stream = derive_voucher_stream(mint.voucher)
    assert stream.voucher_write_cap == mint.voucher_write_cap
    assert stream.voucher_read_cap == mint.voucher_read_cap

    induct = voucher_induct(mint.voucher, mint.voucher_payload, WHO_REPLY)
    assert induct.display_name == "bob"
    assert induct.message_read_cap == bob.read_cap().to_bytes()
    assert induct.voucher_write_cap == mint.voucher_write_cap

    opened = voucher_open_reply(mint.reply_private_key, induct.sealed_reply)
    assert opened.who_reply == WHO_REPLY
    assert opened.salt == induct.salt


def test_mint_is_deterministic_with_reply_seed():
    bob = WriteCap.generate().to_bytes()
    m1 = voucher_mint(bob, "bob", reply_seed=REPLY_SEED)
    m2 = voucher_mint(bob, "bob", reply_seed=REPLY_SEED)
    assert m1 == m2


def test_induct_is_deterministic_with_salt_and_seal_seed():
    bob = WriteCap.generate().to_bytes()
    mint = voucher_mint(bob, "bob", reply_seed=REPLY_SEED)
    i1 = voucher_induct(
        mint.voucher, mint.voucher_payload, WHO_REPLY, salt=SALT, seal_seed=SEAL_SEED
    )
    i2 = voucher_induct(
        mint.voucher, mint.voucher_payload, WHO_REPLY, salt=SALT, seal_seed=SEAL_SEED
    )
    assert i1 == i2
    assert i1.salt == SALT
    # and it round-trips
    opened = voucher_open_reply(mint.reply_private_key, i1.sealed_reply)
    assert opened.who_reply == WHO_REPLY
    assert opened.salt == SALT


def test_reply_key_layout_is_x25519_first():
    # X25519 public (32) + CTIDH1024 public (128) = 160; private = 32 + 130 = 162.
    mint = voucher_mint(WriteCap.generate().to_bytes(), "bob")
    assert len(mint.reply_public_key) == 160
    assert len(mint.reply_private_key) == 162


def test_hash_mismatch_is_detected():
    bob = WriteCap.generate().to_bytes()
    mint = voucher_mint(bob, "bob")
    tampered = bytearray(mint.voucher_payload)
    tampered[0] ^= 0xFF
    with pytest.raises(VoucherHashMismatch):
        voucher_induct(mint.voucher, bytes(tampered), WHO_REPLY)


def test_bad_signature_is_rejected():
    # Forge a SignedPleaseAdd with a zeroed signature, then build a Voucher
    # that genuinely hashes to its payload, so the hash check passes and the
    # signature check is what fails.
    bob = WriteCap.generate()
    _reply_priv, reply_pub = stateless.new_reply_keypair()
    good = stateless.make_signed_please_add(bob, "bob")
    forged = SignedPleaseAdd(good.please_add, bytes(64))
    voucher_hash, payload = stateless.assemble_voucher_payload(forged, reply_pub)
    with pytest.raises(SignatureVerificationFailed):
        voucher_induct(voucher_hash, payload, WHO_REPLY)


def test_wrong_reply_key_cannot_open_seal():
    bob = WriteCap.generate().to_bytes()
    mint_a = voucher_mint(bob, "bob")
    mint_b = voucher_mint(WriteCap.generate().to_bytes(), "carol")
    induct = voucher_induct(mint_a.voucher, mint_a.voucher_payload, WHO_REPLY)
    with pytest.raises(SealOpenFailed):
        voucher_open_reply(mint_b.reply_private_key, induct.sealed_reply)
