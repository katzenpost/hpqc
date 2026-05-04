# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""Vector-driven tests for the cryptographic primitives BACAP depends on.

Each vector file under vectors/ is a per-file symlink into the canonical
testvectors/ tree at the repo root. The same files are consumed by the Go
side at bacap/primitive_vectors_test.go, so any divergence between the Go
and Python implementations of these primitives surfaces here as a failed
assertion.

The primitives covered are:

  - SHA-512/256 (FIPS 180-4 §6.7)
  - BLAKE2b-512 (RFC 7693)
  - HKDF with BLAKE2b-512 as the underlying hash (RFC 5869)
  - AES-256-GCM-SIV (RFC 8452)

These tests do not depend on the hpqc Python package; they exercise the
underlying library implementations (hashlib, cryptography) that the eventual
hpqc port will use as building blocks. Once the port lands the tests can be
rewritten to call hpqc's wrappers, but for now they pin the behaviour we
expect the wrappers to inherit.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

VECTORS_DIR = Path(__file__).parent / "vectors"


def _load(name: str, primitive: str) -> list[dict]:
    with (VECTORS_DIR / name).open("rb") as f:
        doc = json.load(f)
    assert doc["format_version"] == 1, f"unexpected format_version in {name}"
    assert doc["primitive"] == primitive, (
        f"{name}: expected primitive {primitive!r}, got {doc['primitive']!r}"
    )
    assert doc["vectors"], f"{name}: empty vectors array"
    return doc["vectors"]


# SHA-512/256 ---------------------------------------------------------------


@pytest.mark.parametrize(
    "vector",
    _load("sha512_256.json", "sha512_256"),
    ids=lambda v: v["name"],
)
def test_sha512_256(vector: dict) -> None:
    h = hashlib.new("sha512_256")
    h.update(bytes.fromhex(vector["input_hex"]))
    assert h.digest() == bytes.fromhex(vector["output_hex"])


# BLAKE2b-512 ---------------------------------------------------------------


@pytest.mark.parametrize(
    "vector",
    _load("blake2b_512.json", "blake2b_512"),
    ids=lambda v: v["name"],
)
def test_blake2b_512(vector: dict) -> None:
    h = hashlib.blake2b(digest_size=64)
    h.update(bytes.fromhex(vector["input_hex"]))
    assert h.digest() == bytes.fromhex(vector["output_hex"])


# HKDF-BLAKE2b-512 ----------------------------------------------------------
#
# Two implementations are checked against the same vectors:
#
#   - cryptography.hazmat.primitives.kdf.hkdf.HKDF with hashes.BLAKE2b(64),
#     which is what the eventual hpqc port will use for the high-level case
#     where the entire OKM is consumed at once.
#
#   - A hand-rolled RFC 5869 implementation over HMAC-BLAKE2b-512 in plain
#     hashing mode, which is the shape needed for streaming reads (Go's
#     hkdf.New returns an io.Reader and BACAP reads from it incrementally
#     in MessageBoxIndex.AdvanceIndexTo).
#
# The two implementations must agree byte-for-byte with the Go reference.


def _hkdf_blake2b_streaming(secret: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """Pure-stdlib HKDF-BLAKE2b-512 per RFC 5869, suitable for streaming."""
    digest_size = 64
    if not salt:
        salt = b"\x00" * digest_size
    prk = hmac.new(salt, secret, hashlib.blake2b).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.blake2b).digest()
        out += t
        counter += 1
    return out[:length]


@pytest.mark.parametrize(
    "vector",
    _load("hkdf_blake2b.json", "hkdf_blake2b"),
    ids=lambda v: v["name"],
)
def test_hkdf_blake2b_streaming_impl(vector: dict) -> None:
    out = _hkdf_blake2b_streaming(
        bytes.fromhex(vector["secret_hex"]),
        bytes.fromhex(vector["salt_hex"]),
        bytes.fromhex(vector["info_hex"]),
        vector["length"],
    )
    assert out == bytes.fromhex(vector["okm_hex"])


@pytest.mark.parametrize(
    "vector",
    _load("hkdf_blake2b.json", "hkdf_blake2b"),
    ids=lambda v: v["name"],
)
def test_hkdf_blake2b_cryptography_impl(vector: dict) -> None:
    salt = bytes.fromhex(vector["salt_hex"]) or None
    info = bytes.fromhex(vector["info_hex"]) or None
    secret = bytes.fromhex(vector["secret_hex"])
    okm = HKDF(
        algorithm=hashes.BLAKE2b(64),
        length=vector["length"],
        salt=salt,
        info=info,
    ).derive(secret)
    assert okm == bytes.fromhex(vector["okm_hex"])


# AES-256-GCM-SIV ----------------------------------------------------------


@pytest.mark.parametrize(
    "vector",
    _load("aes_gcm_siv.json", "aes_gcm_siv"),
    ids=lambda v: v["name"],
)
def test_aes_gcm_siv(vector: dict) -> None:
    key = bytes.fromhex(vector["key_hex"])
    nonce = bytes.fromhex(vector["nonce_hex"])
    aad = bytes.fromhex(vector["aad_hex"])
    plaintext = bytes.fromhex(vector["plaintext_hex"])
    expected_ct = bytes.fromhex(vector["ciphertext_hex"])

    if not plaintext:
        # python-cryptography's AESGCMSIV rejects zero-length plaintext with
        # "data must not be zero length", even though RFC 8452 permits it and
        # the Go implementation handles it. The vector is still meaningful to
        # the Go side; here it is simply outside what python-cryptography
        # exposes.
        pytest.skip("python-cryptography rejects zero-length plaintext")

    siv = AESGCMSIV(key)
    ct = siv.encrypt(nonce, plaintext, aad)
    assert ct == expected_ct, "encryption mismatch"

    pt = siv.decrypt(nonce, expected_ct, aad)
    assert pt == plaintext, "decryption mismatch"
