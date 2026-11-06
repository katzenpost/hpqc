# CTIDH

hpqc includes [CTIDH](https://ctidh.isogeny.org/), a post-quantum NIKE based
on isogenies of supersingular elliptic curves, at field sizes 511, 512, 1024
and 2048. Back to the [README](../README.md).

The Go packages under `nike/ctidh/` wrap the cgo bindings of
[highctidh](https://codeberg.org/vula/highctidh), which maintains them; the
Python port wraps the `highctidh` package from PyPI. If you use CTIDH, read
the highctidh README. The notes below on the Go bindings come from it.

## musl libc and cgo

The Go bindings work with musl libc for field sizes 511 and 512 without any
configuration. For field sizes 1024 and 2048, Go users building with musl
libc need to raise the default stack size at build time, to a multiple of the
page size.

For GNU/Linux:

```
CGO_LDFLAGS: -Wl,-z,stack-size=0x1F40000
```

For macOS:

```
CGO_LDFLAGS: -Wl,-stack_size,0x1F40000
```
