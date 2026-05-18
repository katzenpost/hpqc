# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic proof of the initial-index masking bound.

Mirror of the Go ``TestInitialIndexMaskingBound``. It is a proof,
not a sampler.

Why one input is a proof. ``idx = LE(b[0:8]) + LE(b[8:16])`` where
the only operation on the entropy is clearing bits (the ``&=``
masks). Setting an entropy bit can only raise a little-endian half
or leave it unchanged (if that bit is masked away); it can never
lower it. ``idx`` is therefore monotonic non-decreasing in every one
of its 128 entropy bits, so its maximum over all 2**128 inputs is at
the all-ones input. Establishing the bound there establishes it
everywhere; the all-zero input pins the floor.
"""
from __future__ import annotations

BOUND = 1 << 63              # first unusable index
SUMMAND_MAX = (1 << 62) - 1  # largest 62-bit half
EXPECTED_MAX = (1 << 63) - 2 # 2 * SUMMAND_MAX
U64 = (1 << 64) - 1


def _idx(idx_bytes: bytes) -> int:
    a = int.from_bytes(idx_bytes[:8], "little")
    b = int.from_bytes(idx_bytes[8:], "little")
    return a, b


def test_initial_index_masking_bound() -> None:
    # Supremum: every entropy byte set. Monotonicity makes this the
    # largest idx the function can ever produce.
    all_ones = bytearray(b"\xff" * 16)

    # New (correct) masking: clear the top two bits of each half's
    # most-significant byte (little-endian -> index 7/15).
    nw = bytearray(all_ones)
    nw[7] &= 0x3F
    nw[15] &= 0x3F
    new_lo, new_hi = _idx(nw)
    assert new_lo == SUMMAND_MAX, "max low half must be exactly 2**62-1"
    assert new_hi == SUMMAND_MAX, "max high half must be exactly 2**62-1"
    new_sum = new_lo + new_hi
    assert new_sum == EXPECTED_MAX, "max idx must be exactly 2**63-2"
    assert new_sum < BOUND, (
        f"QED: the largest possible idx ({new_sum}) is < 2**63, so EVERY "
        f"idx is, leaving >= 2**63 usable indices"
    )

    # Old (buggy) masking: cleared the LEAST-significant byte
    # (index 0/8), leaving each half's high bytes fully random.
    ow = bytearray(all_ones)
    ow[0] &= 0x2F
    ow[8] &= 0x2F
    old_lo, old_hi = _idx(ow)
    assert old_lo >= BOUND, (
        f"the old masking let a SINGLE half ({old_lo}) reach >= 2**63, "
        f"already violating the bound"
    )
    # Go's uint64 addition wraps; replicate to show the stored idx
    # becomes an arbitrary wrapped value, not a bounded one.
    old_sum_wrapped = (old_lo + old_hi) & U64
    assert old_sum_wrapped < old_lo, (
        "the old two-half sum (~2**65) wraps the 64-bit accumulator to an "
        "arbitrary index: proof the old way was wrong"
    )

    # Floor: no entropy => idx = 0, so the range is exactly
    # [0, 2**63-2].
    zero = bytearray(16)
    zero[7] &= 0x3F
    zero[15] &= 0x3F
    z_lo, z_hi = _idx(zero)
    assert z_lo + z_hi == 0, "min idx must be 0"
