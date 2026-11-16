# Building and testing

Back to the [README](../README.md).

## Go

The Go packages need cgo and a C compiler: CTIDH, Falcon and SPHINCS+ are C.
CTIDH has its own build notes for musl libc in [ctidh.md](ctidh.md).

```sh
go build ./...
go test ./...
```

CI runs the tests on Linux, macOS and Windows (MSYS2), and cross-compiles for
other architectures.

## Python

The test suite is not shipped in the wheel; run it from a clone:

```sh
cd py
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[test]"
pytest
```

## Rust

```sh
cd rust
cargo test
```

## Test vectors

The Go, Python and Rust tests read the same JSON vectors, so any divergence
between the implementations fails a test. The Python tests read copies, which
`py/tests/test_vector_copies.py` keeps identical to the canonical files.
[testvectors/README.md](../testvectors/README.md) describes the files and how
to regenerate them.

## Debian packages

`debian/` builds two packages, `golang-github-katzenpost-hpqc-dev` (the Go
source) and `python3-hpqc`. `make deb` builds them in a Podman container for
`DISTRO` (default `debian-13`; CI also builds `debian-forky` and
`ubuntu-26.04`) and writes them to `dist/`:

```sh
make deb DISTRO=debian-13
```

`make deb-test` checks an installed package.
