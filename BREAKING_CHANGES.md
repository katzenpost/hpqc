<!--
SPDX-FileCopyrightText: © 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-->

# Breaking changes

This file collects wire-format and API changes that break compatibility
with previously-released versions of `hpqc`. Each entry should make it
clear what changed, why, and what callers need to do.

## BACAP nonce shrunk from 16 to 12 bytes

`bacap.MessageBoxIndex.EncryptForContext` (and `DecryptForContext`)
previously fed a 16-byte nonce — `mICtx[:16]` — to AES-256-GCM-SIV. RFC
8452 mandates a 12-byte nonce, and `agl/gcmsiv` was the only AEAD
library that silently accepted the longer one (using the first 12 bytes
for key derivation and XORing the trailing four into the tag-input
block). No standards-compliant AES-GCM-SIV implementation, including
`python-cryptography`'s `AESGCMSIV`, will reproduce this construction,
which made a Python port of BACAP impossible without re-implementing
AES-GCM-SIV.

We now use `mICtx[:12]` as the nonce; the AAD remains the full 32-byte
box ID. This is a one-shot wire-format break: any box encrypted under
the previous code is no longer decryptable with the current code, and
vice versa.

See: <https://github.com/katzenpost/hpqc/issues/96>.

## NIKE hybrid `CTIDH1024-X25519` field order swap

`hybrid.CTIDH1024X25519` was named `"CTIDH1024-X25519"` but had
`first: x25519.Scheme(...)` and `second: ctidh1024.Scheme(...)` in its
struct literal, so the wire format was actually
`x25519_pubkey || ctidh1024_pubkey` and likewise for private keys and
shared secrets. The label and the layout disagreed.

We now have `first: ctidh1024.Scheme(...)` and
`second: x25519.Scheme(...)`, so the wire layout is
`ctidh1024_pubkey || x25519_pubkey`, which is what the name has always
implied. This breaks compatibility with any deployed key, ciphertext,
or shared secret produced under the old ordering.

The same labelling defect exists in `CTIDH511X25519`, `CTIDH512X25519`,
and `CTIDH512X448`. They are not corrected in this change because no
internal code depends on them, and changing them silently would break
any downstream consumer that has accommodated the existing layout. They
should be either fixed or renamed in a future change.

## KEM combiner SplitPRF input encoding

`util.SplitPRF` now domain-separates and length-prefixes its inputs:

	hash_i := BLAKE2b-256(
	    "splitprf-v1" ||
	    u32be(len(ss_i))    || ss_i ||
	    u32be(n)            ||
	    u32be(len(cct_1))   || cct_1 ||
	    ...                 ||
	    u32be(len(cct_n))   || cct_n
	)

Previously the input was the unprefixed `ss_i || cct_1 || ... || cct_n`.
The change makes the construction unambiguous when sub-KEMs have
variable-size shared secrets or ciphertexts, but it changes the bytes
of every shared key produced by `kem/combiner` and the legacy
`kem/hybrid`. Any deployed system that has persisted or compared a
combiner shared secret across versions will see a mismatch.
