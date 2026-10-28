# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the sealed box construction, mirroring the Go tests."""
from __future__ import annotations

import os

import pytest

from hpqc.nike.ctidh1024 import CTIDH1024
from hpqc.nike.hybrid import HybridNIKE
from hpqc.nike.scheme import Scheme as NIKEScheme
from hpqc.nike.x25519 import X25519
from hpqc.protocols.sealedbox import (
    DegenerateSharedSecretError,
    KeySchemeError,
    OpenError,
    SealedBoxScheme,
)


def _x25519_ctidh1024() -> HybridNIKE:
    return HybridNIKE(X25519(), CTIDH1024(), name="X25519-CTIDH1024")


@pytest.fixture(params=[X25519(), _x25519_ctidh1024()], ids=lambda s: s.name)
def nike(request: pytest.FixtureRequest) -> NIKEScheme:
    return request.param


@pytest.mark.parametrize("size", [0, 1, 32, 1500])
def test_round_trip(nike: NIKEScheme, size: int) -> None:
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair()
    plaintext = os.urandom(size)
    ct = s.seal(pub, plaintext)
    assert len(ct) == size + s.overhead
    assert s.open(priv, pub, ct) == plaintext


def test_overhead_and_name() -> None:
    s = SealedBoxScheme(_x25519_ctidh1024())
    assert s.overhead == 176
    assert s.name == "sealedbox-X25519-CTIDH1024"


def test_fresh_ephemeral() -> None:
    nike = X25519()
    s = SealedBoxScheme(nike)
    pub, _ = nike.generate_keypair()
    assert s.seal(pub, b"same") != s.seal(pub, b"same")


def test_wrong_recipient(nike: NIKEScheme) -> None:
    s = SealedBoxScheme(nike)
    pub, _ = nike.generate_keypair()
    other_pub, other = nike.generate_keypair()
    ct = s.seal(pub, b"for someone else")
    with pytest.raises(OpenError):
        s.open(other, other_pub, ct)


def test_mismatched_public_key() -> None:
    nike = X25519()
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair()
    other_pub, _ = nike.generate_keypair()
    ct = s.seal(pub, b"payload")
    with pytest.raises(OpenError):
        s.open(priv, other_pub, ct)


def test_tamper() -> None:
    nike = X25519()
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair()
    ct = s.seal(pub, b"do not touch")
    for i in range(len(ct)):
        for bit in (0x01, 0x80):
            bad = bytearray(ct)
            bad[i] ^= bit
            with pytest.raises(OpenError):
                s.open(priv, pub, bytes(bad))


def test_truncated(nike: NIKEScheme) -> None:
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair()
    ct = s.seal(pub, b"whole")
    for n in (0, 1, nike.public_key_size, s.overhead - 1, s.overhead, len(ct) - 1):
        with pytest.raises(OpenError):
            s.open(priv, pub, ct[:n])


def test_degenerate_ephemeral(nike: NIKEScheme) -> None:
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair()
    ct = s.seal(pub, b"payload")
    # A zero X25519 point, alone or as the X25519 half of the hybrid,
    # makes the shared secret degenerate.
    bad = bytes(32) + ct[32:]
    with pytest.raises(OpenError):
        s.open(priv, pub, bad)


def test_degenerate_recipient(nike: NIKEScheme) -> None:
    s = SealedBoxScheme(nike)
    pub, _ = nike.generate_keypair()
    degenerate = nike.public_key_from_bytes(bytes(32) + pub.to_bytes()[32:])
    with pytest.raises(DegenerateSharedSecretError):
        s.seal(degenerate, b"payload")


def test_key_of_other_scheme() -> None:
    x = X25519()
    x_pub, x_priv = x.generate_keypair()
    nike = _x25519_ctidh1024()
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair()

    with pytest.raises(KeySchemeError):
        s.seal(x_pub, b"payload")

    ct = s.seal(pub, b"payload")
    with pytest.raises(OpenError):
        s.open(x_priv, pub, ct)
    with pytest.raises(OpenError):
        s.open(priv, x_pub, ct)


def test_none_keys() -> None:
    nike = X25519()
    s = SealedBoxScheme(nike)
    pub, priv = nike.generate_keypair()
    with pytest.raises(KeySchemeError):
        s.seal(None, b"payload")  # type: ignore[arg-type]
    ct = s.seal(pub, b"payload")
    with pytest.raises(OpenError):
        s.open(None, pub, ct)  # type: ignore[arg-type]
    with pytest.raises(OpenError):
        s.open(priv, None, ct)  # type: ignore[arg-type]
