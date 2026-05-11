# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""Falcon-padded-512 signature verification, Scheme-shaped.

Backed by ``pqcrypto.sign.falcon_padded_512.verify`` (which vendors
PQClean's reference C). The class is verify-only by design; sign and
keygen are deliberately not exposed in the Python port.
"""

from __future__ import annotations

from pqcrypto.sign import falcon_padded_512 as _f512


class FalconPadded512Scheme:
    """Verify-only Falcon-padded-512.

    Sizes mirror the Go side and match ``pqcrypto``'s constants. The
    class is intentionally a simple value object so it can compose into
    :class:`hpqc.sign.hybrid.HybridSignScheme` alongside a classical
    verifier.
    """

    name: str = "Falcon-padded-512"
    public_key_size: int = _f512.PUBLIC_KEY_SIZE
    signature_size: int = _f512.SIGNATURE_SIZE

    @staticmethod
    def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != FalconPadded512Scheme.public_key_size:
            return False
        if len(signature) != FalconPadded512Scheme.signature_size:
            return False
        return bool(_f512.verify(public_key, message, signature))


__all__ = ["FalconPadded512Scheme"]
