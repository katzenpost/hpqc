

# HPQC

[![Go Reference](https://pkg.go.dev/badge/github.com/katzenpost/hpqc.svg)](https://pkg.go.dev/github.com/katzenpost/hpqc)
[![Release](https://img.shields.io/github/v/tag/katzenpost/hpqc)](https://github.com/katzenpost/hpqc/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/katzenpost/hpqc)](https://goreportcard.com/report/github.com/katzenpost/hpqc)
[![CI](https://github.com/katzenpost/hpqc/actions/workflows/go.yml/badge.svg)](https://github.com/katzenpost/hpqc/actions/workflows/go.yml)



## hybrid post quantum cryptography

hpqc is a golang cryptography library. hpqc is used by the Katzenpost Sphinx based mixnet.
The theme of the library is hybrid post quantum constructions, namely:

* hybrid KEMs
* hybrid NIKEs
* hybrid signature schemes

This library makes some unique contributions in golang:

1. a set of generic NIKE interfaces for NIKE scheme, public key and private key types
2. generic hybrid NIKE, combines any two NIKEs into one
3. secure KEM combiner that can combine an arbtrary number of KEMs into one KEM
4. a "NIKE to KEM adapter" which uses an ad hoc hashed elgamal construction
5. cgo bindings for the Sphincs+ C reference source
6. cgo bindings for the CTIDH C source
7. generic hybrid signature scheme, combines any two signature schemes into one




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

The KEM Combiners paper [KEMCOMB](https://eprint.iacr.org/2018/024.pdf) makes the
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



## cryptographic primitives


| NIKE: Non-Interactive Key Exchange |
|:---:|
* X25519
* CTIDH511, CTIDH512, CTIDH1024, CTIDH2048
* X25519_CTIDH511, X25519_CTIDH512, X25519_CTIDH1024, X25519_CTIDH2048
* NOBS_CSIDH-512
* X25519_NOBS_CSIDH-512

| KEM: Key Encapsulation Methods |
|:---:|
* X25519 (adapted via ad hoc hashed elgamal construction)
* CTIDH1024 (adapted via ad hoc hashed elgamal construction)
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



## licensing

hpqc is free libre open source software (FLOSS) under the AGPL-3.0 software license.
This git repository provides a LICENSE file, here: https://github.com/katzenpost/hpqc/blob/main/LICENSE


Read about free software philosophy --> https://www.gnu.org/philosophy/free-sw.html


* There are precisely two files which were borrowed
from cloudflare's `circl` cryptography library
which provide the kem and signature interfaces:

1. https://github.com/katzenpost/hpqc/blob/main/kem/interfaces.go
2. https://github.com/katzenpost/hpqc/blob/main/sign/interfaces.go

Those two files have their licenses attached at the top in a code comment.
