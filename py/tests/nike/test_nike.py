# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Round-trip tests for the NIKE schemes.

The same test functions are run against every available scheme via
``pytest.mark.parametrize``: X25519, CTIDH1024, and the hybrid
``CTIDH1024-X25519``. Each scheme is exercised end-to-end:

  - keypair generation
  - shared-secret agreement (Alice's secret == Bob's secret)
  - key serialise/deserialise round-trip
  - reported sizes match the actual byte lengths
  - mixing keys from different schemes is rejected with a clear error
"""
from __future__ import annotations

import pytest

from hpqc.nike import PrivateKey, PublicKey, Scheme
from hpqc.nike.ctidh511 import CTIDH511
from hpqc.nike.ctidh512 import CTIDH512
from hpqc.nike.ctidh1024 import CTIDH1024
from hpqc.nike.ctidh2048 import CTIDH2048
from hpqc.nike.hybrid import HybridNIKE
from hpqc.nike.x25519 import X25519


def _all_schemes() -> list[Scheme]:
    return [
        X25519(),
        CTIDH511(),
        CTIDH512(),
        CTIDH1024(),
        CTIDH2048(),
        HybridNIKE(CTIDH1024(), X25519()),
    ]


@pytest.fixture(params=_all_schemes(), ids=lambda s: s.name)
def scheme(request: pytest.FixtureRequest) -> Scheme:
    return request.param


# ----- name and size sanity -----


def test_name_is_nonempty(scheme: Scheme) -> None:
    assert scheme.name


def test_sizes_are_positive(scheme: Scheme) -> None:
    assert scheme.public_key_size > 0
    assert scheme.private_key_size > 0


# ----- generate, derive, agree -----


def test_generate_keypair_returns_matching_pair(scheme: Scheme) -> None:
    pub, priv = scheme.generate_keypair()
    assert isinstance(pub, PublicKey)
    assert isinstance(priv, PrivateKey)
    derived = scheme.derive_public_key(priv)
    assert derived.to_bytes() == pub.to_bytes()


def test_keypair_byte_sizes_match_scheme(scheme: Scheme) -> None:
    pub, priv = scheme.generate_keypair()
    assert len(pub.to_bytes()) == scheme.public_key_size
    assert len(priv.to_bytes()) == scheme.private_key_size


def test_alice_and_bob_agree(scheme: Scheme) -> None:
    alice_pub, alice_priv = scheme.generate_keypair()
    bob_pub, bob_priv = scheme.generate_keypair()
    s_alice = scheme.derive_secret(alice_priv, bob_pub)
    s_bob = scheme.derive_secret(bob_priv, alice_pub)
    assert s_alice == s_bob
    assert len(s_alice) > 0


# ----- serialise / deserialise -----


def test_public_key_round_trip(scheme: Scheme) -> None:
    pub, _ = scheme.generate_keypair()
    blob = pub.to_bytes()
    pub2 = scheme.public_key_from_bytes(blob)
    assert pub2.to_bytes() == blob


def test_private_key_round_trip(scheme: Scheme) -> None:
    _, priv = scheme.generate_keypair()
    blob = priv.to_bytes()
    priv2 = scheme.private_key_from_bytes(blob)
    assert priv2.to_bytes() == blob


def test_round_trip_preserves_dh(scheme: Scheme) -> None:
    """A deserialised private key still produces the same shared secret."""
    alice_pub, alice_priv = scheme.generate_keypair()
    bob_pub, bob_priv = scheme.generate_keypair()

    alice_priv_re = scheme.private_key_from_bytes(alice_priv.to_bytes())
    bob_pub_re = scheme.public_key_from_bytes(bob_pub.to_bytes())

    assert (
        scheme.derive_secret(alice_priv, bob_pub)
        == scheme.derive_secret(alice_priv_re, bob_pub_re)
    )


# ----- type-safety -----


def test_cross_scheme_keys_rejected() -> None:
    """Feeding a key from one scheme into another raises clearly."""
    x = X25519()
    c = CTIDH1024()

    x_pub, x_priv = x.generate_keypair()
    c_pub, c_priv = c.generate_keypair()

    with pytest.raises(TypeError):
        c.derive_secret(x_priv, c_pub)
    with pytest.raises(TypeError):
        c.derive_secret(c_priv, x_pub)
    with pytest.raises(TypeError):
        x.derive_secret(c_priv, x_pub)


# ----- hybrid-specific properties -----


def test_hybrid_serialised_layout_is_concatenation() -> None:
    """A hybrid public key on the wire is first||second, exactly."""
    first = CTIDH1024()
    second = X25519()
    hybrid = HybridNIKE(first, second)

    pub, priv = hybrid.generate_keypair()
    pub_bytes = pub.to_bytes()
    priv_bytes = priv.to_bytes()

    assert pub_bytes == pub.first.to_bytes() + pub.second.to_bytes()
    assert priv_bytes == priv.first.to_bytes() + priv.second.to_bytes()
    assert len(pub_bytes) == first.public_key_size + second.public_key_size
    assert len(priv_bytes) == first.private_key_size + second.private_key_size


def test_hybrid_secret_layout_is_concatenation() -> None:
    """The hybrid shared secret is first.dh || second.dh, exactly."""
    first = CTIDH1024()
    second = X25519()
    hybrid = HybridNIKE(first, second)

    a_pub, a_priv = hybrid.generate_keypair()
    b_pub, b_priv = hybrid.generate_keypair()

    s = hybrid.derive_secret(a_priv, b_pub)
    expected = (
        first.derive_secret(a_priv.first, b_pub.first)
        + second.derive_secret(a_priv.second, b_pub.second)
    )
    assert s == expected


def test_hybrid_name_is_dash_joined() -> None:
    assert HybridNIKE(CTIDH1024(), X25519()).name == "ctidh1024-x25519"
