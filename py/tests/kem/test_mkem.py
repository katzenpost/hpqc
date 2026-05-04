# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Round-trip tests for the MKEM construction.

Run against every NIKE scheme so the MKEM is exercised over X25519,
CTIDH1024, and the hybrid combiner. Each test covers one of the
following scenarios:

  - single-recipient envelope_reply / decrypt_envelope
  - multi-recipient encapsulate / decapsulate (3 recipients; each
    recovers the payload, and a non-recipient is rejected)
  - ciphertext CBOR marshal / ciphertext_from_bytes round-trip
"""
from __future__ import annotations

import pytest

from hpqc.kem.mkem import DEKSize, MKEMScheme
from hpqc.nike.ctidh1024 import CTIDH1024
from hpqc.nike.hybrid import HybridNIKE
from hpqc.nike.scheme import Scheme as NIKEScheme
from hpqc.nike.x25519 import X25519


def _all_nikes() -> list[NIKEScheme]:
    return [
        X25519(),
        CTIDH1024(),
        HybridNIKE(CTIDH1024(), X25519()),
    ]


@pytest.fixture(params=_all_nikes(), ids=lambda s: s.name)
def mkem(request: pytest.FixtureRequest) -> MKEMScheme:
    return MKEMScheme(request.param)


# ----- single-recipient envelope -----


def test_envelope_reply_round_trip(mkem: MKEMScheme) -> None:
    alice_pub, alice_priv = mkem.generate_keypair()
    bob_pub, bob_priv = mkem.generate_keypair()

    payload = b"the eagle has landed"
    ct = mkem.envelope_reply(alice_priv, bob_pub, payload)

    # Bob reverses roles to recover the payload.
    recovered = mkem.decrypt_envelope(bob_priv, alice_pub, ct.envelope)
    assert recovered == payload


def test_envelope_reply_rejects_wrong_key(mkem: MKEMScheme) -> None:
    alice_pub, alice_priv = mkem.generate_keypair()
    bob_pub, bob_priv = mkem.generate_keypair()
    eve_pub, eve_priv = mkem.generate_keypair()

    ct = mkem.envelope_reply(alice_priv, bob_pub, b"secret")
    with pytest.raises(Exception):
        mkem.decrypt_envelope(eve_priv, alice_pub, ct.envelope)


# ----- multi-recipient encapsulation -----


def test_encapsulate_three_recipients_each_recovers(mkem: MKEMScheme) -> None:
    pubs_privs = [mkem.generate_keypair() for _ in range(3)]
    pubs = [p for p, _ in pubs_privs]
    privs = [s for _, s in pubs_privs]

    payload = b"broadcast to all three"
    eph_priv, ct = mkem.encapsulate(pubs, payload)

    assert len(ct.dek_ciphertexts) == 3
    for dek in ct.dek_ciphertexts:
        assert len(dek) == DEKSize

    for priv in privs:
        assert mkem.decapsulate(priv, ct) == payload


def test_encapsulate_rejects_non_recipient(mkem: MKEMScheme) -> None:
    a_pub, a_priv = mkem.generate_keypair()
    b_pub, b_priv = mkem.generate_keypair()
    e_pub, e_priv = mkem.generate_keypair()

    _eph_priv, ct = mkem.encapsulate([a_pub, b_pub], b"not for eve")
    with pytest.raises(ValueError, match="failed to trial decrypt"):
        mkem.decapsulate(e_priv, ct)


def test_encapsulate_requires_at_least_one_key(mkem: MKEMScheme) -> None:
    with pytest.raises(ValueError):
        mkem.encapsulate([], b"x")


# ----- ciphertext serialisation -----


def test_ciphertext_marshal_round_trip(mkem: MKEMScheme) -> None:
    pub, priv = mkem.generate_keypair()
    _, ct = mkem.encapsulate([pub], b"hello marshal")

    blob = ct.marshal()
    ct2 = mkem.ciphertext_from_bytes(blob)

    assert ct2.ephemeral_public_key.to_bytes() == ct.ephemeral_public_key.to_bytes()
    assert ct2.dek_ciphertexts == ct.dek_ciphertexts
    assert ct2.envelope == ct.envelope

    # Round-trip through bytes still decapsulates correctly.
    assert mkem.decapsulate(priv, ct2) == b"hello marshal"
