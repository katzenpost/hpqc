# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""Hybrid signature verification: two Scheme-shaped components composed
into one. The wire format is the simple concatenation used by Go's
``hpqc/sign/hybrid``: public key = first_pub || second_pub, signature
= first_sig || second_sig.
"""

from .hybrid import HybridSignScheme, __all__


def __getattr__(name: str) -> "HybridSignScheme":
    from . import hybrid

    return getattr(hybrid, name)
