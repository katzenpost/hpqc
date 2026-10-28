# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""The vector files under tests/**/vectors/ are copies of the canonical
JSON in the repository, mostly under testvectors/, which the Go tests
read.

They are copies rather than symlinks so that the sdist carries real
files. This test fails when a copy drifts from its canonical file, or
when a copy is not listed here. It is skipped outside a repository
checkout, where the canonical files are absent.
"""
from __future__ import annotations

from pathlib import Path

import pytest

PY_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PY_ROOT.parent

# Each copy, relative to py/, and its canonical file, relative to the
# repository root.
COPIES = {
    "tests/bacap/vectors/aes_gcm_siv.json": "testvectors/primitives/aes_gcm_siv.json",
    "tests/bacap/vectors/blake2b_512.json": "testvectors/primitives/blake2b_512.json",
    "tests/bacap/vectors/box_id.json": "testvectors/bacap/box_id.json",
    "tests/bacap/vectors/encrypt.json": "testvectors/bacap/encrypt.json",
    "tests/bacap/vectors/hkdf_blake2b.json": "testvectors/primitives/hkdf_blake2b.json",
    "tests/bacap/vectors/inputs.json": "testvectors/bacap/inputs.json",
    "tests/bacap/vectors/layout.json": "testvectors/bacap/layout.json",
    "tests/bacap/vectors/message_box_index.json": "testvectors/bacap/message_box_index.json",
    "tests/bacap/vectors/mutate_kdf_state.json": "testvectors/bacap/mutate_kdf_state.json",
    "tests/bacap/vectors/negative.json": "testvectors/bacap/negative.json",
    "tests/bacap/vectors/position.json": "testvectors/bacap/position.json",
    "tests/bacap/vectors/sha512_256.json": "testvectors/primitives/sha512_256.json",
    "tests/bacap/vectors/tombstone.json": "testvectors/bacap/tombstone.json",
    "tests/protocols/vectors/mkem.json": "testvectors/kem/mkem.json",
    "tests/protocols/vectors/sealedbox.json": "testvectors/protocols/sealedbox.json",
    "tests/sign/ed25519/vectors/blinded_ed25519.json": "testvectors/primitives/blinded_ed25519.json",
    "tests/sign/ed25519/vectors/ed25519.json": "testvectors/primitives/ed25519.json",
    "tests/sign/falcon/vectors/falcon_padded_512.json": "testvectors/primitives/falcon_padded_512.json",
    "tests/sign/hybrid/vectors/falcon_padded_512_ed25519.json": "testvectors/primitives/falcon_padded_512_ed25519.json",
    "tests/voucher/vectors/voucher_vectors.json": "voucher/testdata/voucher_vectors.json",
}

pytestmark = pytest.mark.skipif(
    not (REPO_ROOT / "testvectors").is_dir(),
    reason="the canonical vectors are only present in a repository checkout",
)


@pytest.mark.parametrize("copy, canonical", sorted(COPIES.items()))
def test_copy_matches(copy: str, canonical: str) -> None:
    path = PY_ROOT / copy
    assert not path.is_symlink(), f"{copy} must be a copy, not a symlink"
    assert path.read_bytes() == (REPO_ROOT / canonical).read_bytes(), (
        f"{copy} differs from {canonical}; from py/ run: cp ../{canonical} {copy}"
    )


def test_every_copy_is_listed() -> None:
    found = {
        p.relative_to(PY_ROOT).as_posix()
        for p in (PY_ROOT / "tests").glob("**/vectors/*.json")
    }
    assert found == set(COPIES)
