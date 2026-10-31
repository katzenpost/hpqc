# Changelog

All notable changes to the `hpqc` Python package are recorded in this
file. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file tracks the **Python port only** (`py/` in
[katzenpost/hpqc](https://github.com/katzenpost/hpqc)). Changes that
affect the Go reference, or that are API-breaking across either
side, are also recorded in the repository-root
[BREAKING_CHANGES.md](https://github.com/katzenpost/hpqc/blob/main/BREAKING_CHANGES.md).


## [Unreleased]


## [0.0.95] - 2026-10-29

### Changed

- The version follows the repository tag; this release is v0.0.95,
  since v0.0.94 was not published.

### Added

- Sealed box (`hpqc.protocols.sealedbox`): anonymous public-key
  encryption to one recipient over any NIKE, a port of the Go
  `protocols/sealedbox`.

### Changed

- MKEM moved from `hpqc.kem.mkem` to `hpqc.protocols.mkem`, beside the
  sealed box. The API is unchanged.
- The test vectors under `tests/**/vectors/` are copies instead of
  symlinks, so the sdist carries them and its tests run; flit_core 4
  is supported again. `tests/test_vector_copies.py` keeps the copies
  identical to the canonical files.


## [0.0.93] - 2026-10-14

### Changed

- The version follows the repository tag; this release is v0.0.93,
  since v0.0.92 was not published.
- Requires highctidh 1.0.2026101300, which rejects the all-zero CTIDH
  public key when decoding; keys from entropy are read little-endian.
- pqcrypto is optional (the `falcon` extra), and cryptography 43,
  pynacl 1.5 and cbor2 5.6 are enough, as in Debian 13.

### Added

- BACAP positions (`ReadPosition`, `WritePosition`), `contains`,
  `start` and `position_at` on both caps, and
  `MessageBoxIndex.open_for_context`, matching the Go API.

### Removed

- `hpqc.bacap.StatefulReader` and `StatefulWriter`. Use positions; the
  repository-root BREAKING_CHANGES.md maps each method to its
  replacement.


## [0.0.2] - 2026-05-11

### Added

- Plain Ed25519 signature verification as a Scheme-shaped value
  object (`hpqc.sign.ed25519.Ed25519Scheme`), alongside the
  existing blinded variants used by BACAP.
- Falcon-padded-512 signature verification
  (`hpqc.sign.falcon.FalconPadded512Scheme`), backed by the
  [`pqcrypto`](https://pypi.org/project/pqcrypto/) runtime
  dependency, which vendors the same PQClean reference C reached
  by the Go side. Verify-only by design; sign and key generation
  remain Go-only.
- Hybrid signature verification (`hpqc.sign.hybrid`): a generic
  two-component combiner plus a pre-registered
  `FalconPadded512Ed25519` instance, mirroring the Go-side
  hybrid scheme of the same name.
- Shared JSON test vectors for the three new verifiers under
  `testvectors/primitives/`, so the Python and Go ports cannot
  drift on the new sign surface.

### Changed

- `pqcrypto >= 0.4.0` is now a runtime dependency. The 0.4.0
  release ships prebuilt wheels for Linux manylinux/musllinux,
  macOS arm64, and Windows x86-64, across Python 3.9 to 3.14, so
  the install path does not require a C compiler on the
  supported wheels.


## [0.0.1] - 2026-05-04

Initial public release.

### Added

- BACAP (`hpqc.bacap`) with both stateless (`MessageBoxIndex`,
  `WriteCap`, `ReadCap`) and stateful (`StatefulReader`,
  `StatefulWriter`) APIs, covering encrypt, decrypt, sign, verify
  and tombstones.
- MKEM (`hpqc.kem.mkem`): multi-recipient KEM construction over
  any NIKE.
- NIKE abstract base classes (`hpqc.nike.scheme`) mirroring the
  Go interfaces, plus concrete X25519 and a generic `HybridNIKE`
  combiner.
- CTIDH wrappers (`hpqc.nike.ctidh{511,512,1024,2048}`) over the
  upstream `highctidh` package, brought under the abstract NIKE
  interface.
- Ed25519 signing (`hpqc.sign.ed25519`), including the blinded
  Ed25519 variant on which BACAP relies.
- Cross-language test vectors shared with the Go reference under
  `testvectors/`, with per-file symlinks under `tests/.../vectors/`
  so the Python and Go sides cannot drift silently.
- PEP 561 `py.typed` marker, so type hints are visible to
  downstream type checkers.


[Unreleased]: https://github.com/katzenpost/hpqc/compare/v0.0.95...HEAD
[0.0.95]: https://github.com/katzenpost/hpqc/compare/v0.0.93...v0.0.95
[0.0.93]: https://github.com/katzenpost/hpqc/compare/py/v0.0.2...v0.0.93
[0.0.2]: https://github.com/katzenpost/hpqc/compare/py/v0.0.1...py/v0.0.2
[0.0.1]: https://github.com/katzenpost/hpqc/releases/tag/py/v0.0.1
