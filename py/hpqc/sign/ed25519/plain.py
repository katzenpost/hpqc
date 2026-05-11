# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""Plain Ed25519 signature verification, wrapped as a Scheme-shaped class.

Sits alongside :mod:`hpqc.sign.ed25519.blinded25519`, which only deals
with the BACAP blinded variants. The class exposed here is the verify-
only counterpart to the Go-side ``sign/ed25519`` scheme registered in
``sign/schemes``: it lets a Python application check a plain Ed25519
signature that was produced by any conformant Ed25519 signer, and
provides the classical half of the
:class:`hpqc.sign.hybrid.HybridSignScheme` composition.
"""

from __future__ import annotations

import nacl.exceptions
import nacl.signing


class Ed25519Scheme:
    """Verify-only plain Ed25519 (RFC 8032), Scheme-shaped.

    Sign and key generation are deliberately not exposed. This class
    is the verifier half of the registered Go ``Ed25519`` scheme and is
    sized to fit any combiner that splits a hybrid signature by component
    size.
    """

    name: str = "Ed25519"
    public_key_size: int = 32
    signature_size: int = 64

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != Ed25519Scheme.public_key_size:
            return False
        if len(signature) != Ed25519Scheme.signature_size:
            return False
        try:
            nacl.signing.VerifyKey(public_key).verify(message, signature)
            return True
        except nacl.exceptions.BadSignatureError:
            return False


__all__ = ["Ed25519Scheme"]
