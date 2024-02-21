

# HPQC

HPQC is known as hpqc.


[![Go Reference](https://pkg.go.dev/badge/github.com/katzenpost/hpqc.svg)](https://pkg.go.dev/github.com/katzenpost/hpqc)
[![Release](https://img.shields.io/github/v/tag/katzenpost/hpqc)](https://github.com/katzenpost/hpqc/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/katzenpost/hpqc)](https://goreportcard.com/report/github.com/katzenpost/hpqc)
[![CI](https://github.com/katzenpost/hpqc/actions/workflows/go.yml/badge.svg)](https://github.com/katzenpost/hpqc/actions/workflows/go.yml)



## hybrid post quantum cryptography

Hybrid cryptographic constructions rely on a classical public key
primitive and a post quantum public key cryptographic primitive, namely:

* hybrid KEMs
* hybrid NIKEs
* hybrid signature schemes

Are main contributions besides a generic NIKE interface and NIKE
combiner is:

1. an implementation of a secure KEM combiner that can combine an arbtrary
number of KEMs.
2. a "NIKE to KEM adapter" which is really an ad hoc hashed elgamal construction

If you want a well known hybrid KEM that has a paper about it then maybe
Xwing is the KEM you are looking for. Otherwise you can construct your own
using our secure KEM combiner and or NIKE to KEM adapter.


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


# licensing

hpqc is free libre open source software (FLOSS) under the AGPL-3.0 software license.
This git repository provides a LICENSE file, here: https://github.com/katzenpost/hpqc/blob/main/LICENSE


Read about free software philosophy --> https://www.gnu.org/philosophy/free-sw.html


* There are precisely two files which were borrowed
from cloudflare's `circl` cryptography library
which provide the kem and signature interfaces:

1. https://github.com/katzenpost/hpqc/blob/main/kem/interfaces.go
2. https://github.com/katzenpost/hpqc/blob/main/sign/interfaces.go

Those two files have their licenses attached at the top in a code comment.
