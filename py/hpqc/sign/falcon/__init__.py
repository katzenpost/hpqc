# SPDX-FileCopyrightText: (c) 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only

"""Verify-only wrappers around Falcon's padded parameter sets.

The wrappers reach into the ``pqcrypto`` PyPI package (which itself
vendors the same PQClean reference C the Go side uses through
``github.com/katzenpost/falcon``), so signatures produced on the Go
side decode byte-for-byte here.
"""

from .padded512 import FalconPadded512Scheme

__all__ = ["FalconPadded512Scheme"]
