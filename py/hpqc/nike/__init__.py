# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""hpqc.nike — generic non-interactive key exchange.

The package exposes the abstract NIKE interface (``Scheme``,
``PublicKey``, ``PrivateKey``) plus concrete implementations:

  - ``hpqc.nike.x25519.X25519`` — classical Curve25519.
  - ``hpqc.nike.ctidh1024.CTIDH1024`` — post-quantum, isogeny-based.
    Requires the ``highctidh`` package; not auto-imported here so
    callers without it can still use the rest of the module.
  - ``hpqc.nike.hybrid.HybridNIKE`` — combiner that exposes two
    NIKEs as one (concatenation of keys and shared secrets).

Typical use::

    from hpqc.nike.x25519 import X25519
    from hpqc.nike.ctidh1024 import CTIDH1024
    from hpqc.nike.hybrid import HybridNIKE

    nike = HybridNIKE(CTIDH1024(), X25519())
    alice_pub, alice_priv = nike.generate_keypair()
    bob_pub, bob_priv = nike.generate_keypair()
    assert nike.derive_secret(alice_priv, bob_pub) == nike.derive_secret(bob_priv, alice_pub)
"""
from .scheme import PrivateKey, PublicKey, Scheme

__all__ = [
    "PrivateKey",
    "PublicKey",
    "Scheme",
]
