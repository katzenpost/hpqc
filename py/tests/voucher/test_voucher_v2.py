# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The compact voucher form: array payload without a signature, sealed box reply; and the two
forms side by side, since an inductor answers in whichever form it was given."""
import json
from pathlib import Path

import cbor2
import pytest

from hpqc.bacap import WriteCap
from hpqc.voucher import (
    SealOpenFailed,
    SignatureVerificationFailed,
    VoucherHashMismatch,
    VoucherPayloadV2,
    payload_version,
    voucher_induct,
    voucher_mint,
    voucher_open_reply,
)
from hpqc.voucher import stateless

_VEC = json.loads((Path(__file__).parent / "vectors" / "voucher_vectors_v2.json").read_text())
_uh = bytes.fromhex
WHO = b"a who reply"
SALT = bytes(range(32))


@pytest.fixture(scope="module")
def bob():
    return WriteCap.generate()


def test_vectors(bob):
    inp = _VEC["inputs"]
    mint = voucher_mint(_uh(inp["message_write_cap"]), inp["display_name"], keypair_seed=_uh(inp["keypair_seed"]))
    for k, v in _VEC["mint"].items():
        assert getattr(mint, k).hex() == v, k
    induct = voucher_induct(mint.voucher, mint.voucher_payload, _uh(inp["who_reply"]), salt=_uh(inp["salt"]), seal_seed=_uh(inp["seal_seed"]))
    assert induct.display_name == _VEC["induct"]["display_name"]
    for k in ("mutated_message_read_cap", "sealed_reply", "voucher_write_cap", "voucher_read_cap", "salt"):
        assert getattr(induct, k).hex() == _VEC["induct"][k], k
    opened = voucher_open_reply(mint.voucher_secret_key, induct.sealed_reply, _uh(inp["message_write_cap"]))
    for k, v in _VEC["open"].items():
        assert getattr(opened, k).hex() == v, k


def test_payload_is_the_array_form(bob):
    mint = voucher_mint(bob.to_bytes(), "bob")
    assert mint.version == 2
    assert payload_version(mint.voucher_payload) == 2
    rc, pk, name, sig = cbor2.loads(mint.voucher_payload)
    assert (rc, pk, name) == (bob.read_cap().to_bytes(), mint.voucher_public_key, "bob")
    assert len(sig) == 64
    assert len(mint.voucher_payload) == 367 + 1 + 3
    assert VoucherPayloadV2.from_bytes(mint.voucher_payload).display_name == "bob"


def test_round_trip_and_sizes(bob):
    mint = voucher_mint(bob.to_bytes(), "bob")
    induct = voucher_induct(mint.voucher, mint.voucher_payload, WHO, salt=SALT)
    assert induct.version == 2
    assert len(induct.sealed_reply) == 160 + 16 + len(cbor2.dumps([WHO, SALT]))
    opened = voucher_open_reply(mint.voucher_secret_key, induct.sealed_reply, bob.to_bytes())
    assert (opened.who_reply, opened.salt) == (WHO, SALT)
    # Writer and reader meet: the mutated caps name the same stream.
    assert WriteCap.from_bytes(opened.mutated_message_write_cap).read_cap().to_bytes() == induct.mutated_message_read_cap


def test_old_payload_is_answered_in_the_old_form(bob):
    mint = voucher_mint(bob.to_bytes(), "bob", version=1)
    assert mint.version == 1 and payload_version(mint.voucher_payload) == 1
    induct = voucher_induct(mint.voucher, mint.voucher_payload, WHO, salt=SALT)
    assert induct.version == 1
    assert isinstance(cbor2.loads(induct.sealed_reply), dict)
    opened = voucher_open_reply(mint.voucher_secret_key, induct.sealed_reply, bob.to_bytes())
    assert (opened.who_reply, opened.salt) == (WHO, SALT)


def test_tampered_payload_is_refused(bob):
    mint = voucher_mint(bob.to_bytes(), "bob")
    rc, pk, name, sig = cbor2.loads(mint.voucher_payload)
    with pytest.raises(VoucherHashMismatch):
        voucher_induct(mint.voucher, cbor2.dumps([rc, pk, "eve", sig]), WHO)


def test_signature_is_checked(bob):
    """A payload whose hash is the voucher but whose signature is not the read cap's own:
    someone naming a stream it does not hold."""
    mint = voucher_mint(bob.to_bytes(), "bob")
    rc, pk, name, sig = cbor2.loads(mint.voucher_payload)
    for bad in (cbor2.dumps([rc, pk, "eve", sig]), cbor2.dumps([rc, pk, name, bytes(64)]), cbor2.dumps([rc, pk, name, sig[:-1] + bytes([sig[-1] ^ 1])])):
        with pytest.raises(SignatureVerificationFailed):
            voucher_induct(stateless.sum256(bad), bad, WHO)
    carol = WriteCap.generate()
    other = cbor2.loads(voucher_mint(carol.to_bytes(), "carol").voucher_payload)[3]
    forged = cbor2.dumps([rc, pk, name, other])
    with pytest.raises(SignatureVerificationFailed):
        voucher_induct(stateless.sum256(forged), forged, WHO)


def test_malformed_payloads_are_refused(bob):
    for bad in (cbor2.dumps([b"x", b"y"]), cbor2.dumps([1, 2, 3]), cbor2.dumps([bob.read_cap().to_bytes(), b"k", "bob"]), b"\x00", b""):
        with pytest.raises(Exception):
            voucher_induct(stateless.sum256(bad), bad, WHO)


def test_wrong_key_cannot_open(bob):
    mint = voucher_mint(bob.to_bytes(), "bob")
    other = voucher_mint(WriteCap.generate().to_bytes(), "carol")
    induct = voucher_induct(mint.voucher, mint.voucher_payload, WHO, salt=SALT)
    with pytest.raises(SealOpenFailed):
        voucher_open_reply(other.voucher_secret_key, induct.sealed_reply, bob.to_bytes())
    with pytest.raises(SealOpenFailed):
        voucher_open_reply(mint.voucher_secret_key, induct.sealed_reply[:-1] + bytes([induct.sealed_reply[-1] ^ 1]), bob.to_bytes())


def test_determinism(bob):
    a = voucher_induct(*_minted(bob), WHO, salt=SALT, seal_seed=b"s" * 32)
    b = voucher_induct(*_minted(bob), WHO, salt=SALT, seal_seed=b"s" * 32)
    assert a.sealed_reply == b.sealed_reply


def _minted(bob):
    m = voucher_mint(bob.to_bytes(), "bob", keypair_seed=b"k" * 32)
    return m.voucher, m.voucher_payload
