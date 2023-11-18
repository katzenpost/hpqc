# HPQC

## hybrid post quantum cryptography

we have but two simple goals at the moment:

1. silo ALL of the katzenpost cryptography into this one library so that it's easier to audit,
easier to reason about. This will help us standardize our approach to solving cryptographic problems
across multiple protocols.
2. Provide a very niche cryptography library that other golang software projects can use if they
want hybrid constructions consisting of classical and post quantum cryptographic primitives.


* hybrid KEMs
* hybrid NIKEs
* hybrid signature schemes



## Additional features are available if you have a C compiler

If your system has a C compiler installed and you know how to set bash environment variables then
getting a few extra features working should be easy:


### CTIDH PQ NIKE

Requires using the `ctidh` tag and setting a bunch of tedious bash environment variables:

```bash
export P=/home/human/code/ctidh_cgo
export CTIDH_BITS=1024
export CGO_CFLAGS="-w -g -I${P} -I${P}/highctidh -DBITS=${CTIDH_BITS}"
export CGO_LDFLAGS="-L${P}/highctidh -Wl,-rpath,${P}/highctidh -lhighctidh_${CTIDH_BITS}"
go test -v --tags=ctidh,Ctidh1024
```

But of course that assumes you've installed our ctidh_cgo library:

https://github.com/katzenpost/ctidh_cgo



### Sphincs+ PQ signature scheme


Currently our sphincsplus is the C reference implementation with only one parameterization.
In order to build with any of the Sphincs+ code you must set the `CGO_CFLAGS_ALLOW` variable
like this, and the required build tag, `sphincsplus`:


```bash

CGO_CFLAGS_ALLOW=-DPARAMS=sphincs-shake-256f go test -v ./... --tags=sphincsplus
```

In the future we can write bindings to hardware optimized libraries.


# licensing

this is agpl-3 licensed code however some modules written by other authors
is included here and in those cases we've included their LICENSE file in the
directory or in the top comment of the file.
