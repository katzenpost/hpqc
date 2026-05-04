<!--
SPDX-FileCopyrightText: © 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-->

# Shared cryptographic test vectors

This directory holds test vectors that are read by **both** the Go and the
Python implementations of `hpqc`. The intention is to ensure byte-for-byte
agreement between the two ports without copy-pasting hex literals into source
files.

## Layout

```
testvectors/
├── primitives/                 # primitives used by BACAP and friends
│   ├── sha512_256.json
│   ├── blake2b_512.json
│   ├── hkdf_blake2b.json
│   ├── aes_gcm_siv.json
│   └── blinded_ed25519.json
├── bacap/                      # BACAP-level vectors (built atop primitives)
│   ├── message_box_index.json
│   ├── box_id.json
│   ├── encrypt_decrypt.json
│   └── stateful.json
└── cmd/
    └── generate/               # Go program that emits the JSON files
        └── main.go
```

The vectors form a hierarchy. If a Python (or Go) implementation fails the
BACAP-level vectors, the primitive-level vectors usually pinpoint where the
divergence is: a wrong HKDF parameter ordering, an off-by-one nonce slice in
blinded Ed25519, an AES-GCM-SIV AAD shape mismatch, and so on.

## How callers reach the vectors

Each test directory that consumes vectors carries a real per-file-symlink
directory pointing into this canonical tree. A directory only exposes the
specific vector files its tests actually read, so listing it is itself
documentation of which vectors those tests depend on.

The directory naming differs by language convention:

- **Go side**: each consuming package has a `testdata/` directory. Go's
  build tooling ignores any directory of that exact name during package
  discovery, so the symlinks do not affect builds.
- **Python side**: each test directory under `py/tests/` has a `vectors/`
  directory. This is the idiomatic name in Python cryptography libraries
  (`pyca/cryptography` uses the same).

For example, the Go side at `sign/ed25519/testdata/`:

```
sign/ed25519/testdata/
└── blinded_ed25519.json -> ../../../testvectors/primitives/blinded_ed25519.json
```

and the equivalent Python side at `py/tests/sign/ed25519/vectors/`:

```
py/tests/sign/ed25519/vectors/
└── blinded_ed25519.json -> ../../../../../testvectors/primitives/blinded_ed25519.json
```

Python tests live under a top-level `py/tests/` tree that mirrors the
package structure under `py/hpqc/`, so the test layout is symmetric with
the package layout without shipping test code in the wheel.

## Regenerating

The vectors are not random. They are emitted by the Go program at
`testvectors/cmd/generate` from the canonical Go primitives. Regenerate with:

```sh
go run ./testvectors/cmd/generate
```

Commit the resulting JSON whenever the primitives change.

## File format

Every file is a JSON object with the same envelope:

```json
{
  "format_version": 1,
  "generator": "github.com/katzenpost/hpqc/testvectors/cmd/generate",
  "primitive": "blinded_ed25519",
  "description": "...",
  "vectors": [ { "name": "...", ... } ]
}
```

Binary fields are hex-encoded strings to keep the files diff-friendly.
