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

Nothing here yet.


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


[Unreleased]: https://github.com/katzenpost/hpqc/compare/py/v0.0.1...HEAD
[0.0.1]: https://github.com/katzenpost/hpqc/releases/tag/py/v0.0.1
