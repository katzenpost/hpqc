# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""hpqc: Python port of katzenpost/hpqc."""

from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("hpqc")
except PackageNotFoundError:
    # Running from a source checkout without an install (e.g.
    # someone imported this directly off disk). The released
    # version is the one in py/pyproject.toml.
    __version__ = "0.0.0+unknown"
