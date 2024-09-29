

# HPQC

[![Go Reference](https://pkg.go.dev/badge/github.com/katzenpost/hpqc.svg)](https://pkg.go.dev/github.com/katzenpost/hpqc)
[![Release](https://img.shields.io/github/v/tag/katzenpost/hpqc)](https://github.com/katzenpost/hpqc/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/katzenpost/hpqc)](https://goreportcard.com/report/github.com/katzenpost/hpqc)
[![CI](https://github.com/katzenpost/hpqc/actions/workflows/go.yml/badge.svg)](https://github.com/katzenpost/hpqc/actions/workflows/go.yml)



## hybrid post quantum cryptography

hpqc is a golang cryptography library. hpqc is used by the Katzenpost mixnet.
The theme of the library is hybrid post quantum cryptographic constructions, namely:

* hybrid KEMs
* hybrid NIKEs
* hybrid signature schemes


The key to understanding and using this cryptography library is to review the `Scheme` interfaces:

* KEM Scheme: https://pkg.go.dev/github.com/katzenpost/hpqc@v0.0.44/kem#Scheme
* NIKE Scheme: https://pkg.go.dev/github.com/katzenpost/hpqc@v0.0.44/nike#Scheme
* Signature Scheme: https://pkg.go.dev/github.com/katzenpost/hpqc@v0.0.44/sign#Scheme

Use our generic NIKE, KEM and Signature scheme interfaces to help you achieve cryptographic agility:

```golang
import ""github.com/katzenpost/hpqc/kem"

func encryptMessage(publicKey kem.PublicKey, scheme kem.Scheme, message []byte) {
        ct, ss, err := scheme.Encapsulate(publicKey)
		if err != nil {
		        panic(err)
		}
		// ...
}
```

* a "NIKE to KEM adapter" which uses an ad hoc hashed elgamal construction.
  The following example code snippet demonstrates how our NIKE to KEM adapter
  satisfies the KEM interfaces and thus can be combined with other KEMs.

* Securely combine any number of NIKEs and KEMs together into a hybrid KEM:

```golang
import (
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/combiner"
	"github.com/katzenpost/hpqc/kem/hybrid"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/circl/kem/frodo/frodo640shake"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
)

var kemScheme kem.Scheme = combiner.New(
		"MLKEM768-Frodo640Shake-CTIDH1024-X448",
		[]kem.Scheme{
		    mlkem768.Scheme(),
			frodo640shake.Scheme(),
			adapter.FromNIKE(ctidh1024.Scheme()),
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
		},
)
```

Cryptographic agility means that if your double ratchet is already using the NIKE interfaces,
then it's trivial to upgrade it to use a hybrid NIKE which appeases the exact same interfaces:

```golang
import (
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

var CTIDH1024X25519 nike.Scheme = &hybrid.Scheme{
	name:   "CTIDH1024-X25519",
	second: ctidh1024.Scheme(),
	first:  x25519.Scheme(rand.Reader),
}
```

* generic hybrid signature scheme, combines any two signature schemes into one

```golang
import (
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

var Ed25519Sphincs = hybrid.New("Ed25519 Sphincs+", ed25519.Scheme(), sphincsplus.Scheme())
```



## NIKE to KEM adapter

Our ad hoc hashed elgamal construction for adapting any NIKE to a KEM is, in pseudo code:

```
func ENCAPSULATE(their_pubkey publickey) ([]byte, []byte) {
    my_privkey, my_pubkey = GEN_KEYPAIR(RNG)
    ss = DH(my_privkey, their_pubkey)
    ss2 = PRF(ss || their_pubkey || my_pubkey)
    return my_pubkey, ss2
}

func DECAPSULATE(my_privkey, their_pubkey) []byte {
    s = DH(my_privkey, their_pubkey)
    shared_key = PRF(ss || my_pubkey || their_pubkey)
    return shared_key
}
```



## KEM Combiner

The [KEM Combiners paper](https://eprint.iacr.org/2018/024.pdf) makes the
observation that if a KEM combiner is not security preserving then the
resulting hybrid KEM will not have IND-CCA2 security if one of the
composing KEMs does not have IND-CCA2 security. Likewise the paper
points out that when using a security preserving KEM combiner, if only
one of the composing KEMs has IND-CCA2 security then the resulting
hybrid KEM will have IND-CCA2 security.

Our KEM combiner uses the split PRF design for an arbitrary number
of kems, here shown with only three, in pseudo code:

```
func SplitPRF(ss1, ss2, ss3, cct1, cct2, cct3 []byte) []byte {
    cct := cct1 || cct2 || cct3
    return PRF(ss1 || cct) XOR PRF(ss2 || cct) XOR PRF(ss3 || cct)
}
```


## The PQ NIKE: CTIDH via highctidh

This library makes available the post quantum NIKE (non-interactive key exchange) known as [CTIDH](https://ctidh.isogeny.org/)
via CGO bindings. However these CGO bindings are now being maintained by the highctidh fork: https://codeberg.org/vula/highctidh.git
That having been said, if you are going to use CTIDH you'll want to read the highctidh README; 
here we reproduce some of the notes about the golang cgo bindings:


### musl libc and cgo

The Golang bindings are compatable with musl libc for field sizes 511
and 512 without any configuration. For field sizes of 1024 and 2048,
Golang users building with musl libc will need to set an environment
variable to increase the default stack size at build time. The stack
size should be a multiple of the page size.

For GNU/Linux:

```
CGO_LDFLAGS: -Wl,-z,stack-size=0x1F40000
```
For MacOS:

```
CGO_LDFLAGS: -Wl,-stack_size,0x1F40000
```


## cryptographic primitives


| NIKE: Non-Interactive Key Exchange |
|:---:|
* Classical Diffiehellman
* X25519
* X448
* CTIDH511, CTIDH512, CTIDH1024, CTIDH2048
* CTIDH512X25519, CTIDH512X448, CTIDH1024X25519, CTIDH1024X448, CTIDH2048X448
* X25519_NOBS_CSIDH-512

| KEM: Key Encapsulation Methods |
|:---:|
* X25519
* CTIDH1024
* CTIDH512-X25519
* CTIDH1024-X448
* MLKEM-768
* Xwing
* McEliece
* NTRUPrime
* Kyber
* FrodoKEM

| SIGN: Cryptographic Signature Schemes |
|:---:|
* ed25519
* sphincs+
* ed25519_sphincs+
* ed25519_dilithium2/3


## Warning

This cryptography library has not had any security review. It should be considered experimental.


## licensing

**HPQC (aka hpqc) is free libre open source software (FLOSS) under the AGPL-3.0 software license.**

* [LICENSE file](https://github.com/katzenpost/hpqc/blob/main/LICENSE).
* [About free software philosophy](https://www.gnu.org/philosophy/free-sw.html)
* There are precisely three files which were borrowed from cloudflare's
`circl` cryptography library:

1. https://github.com/katzenpost/hpqc/blob/main/kem/hybrid/hybrid.go
2. https://github.com/katzenpost/hpqc/blob/main/kem/interfaces.go
3. https://github.com/katzenpost/hpqc/blob/main/sign/interfaces.go

* Classical Diffiehellman implementation from Elixxir/XX Network and modified in place
to conform to our NIKE scheme interfaces, [BSD 2-clause LICENSE file included](https://github.com/katzenpost/hpqc/blob/main/nike/diffiehellman/LICENSE)

https://github.com/katzenpost/hpqc/blob/main/nike/diffiehellman/dh.go
