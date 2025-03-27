

# HPQC

[![Go Reference](https://pkg.go.dev/badge/github.com/katzenpost/hpqc.svg)](https://pkg.go.dev/github.com/katzenpost/hpqc)
[![Release](https://img.shields.io/github/v/tag/katzenpost/hpqc)](https://github.com/katzenpost/hpqc/tags)
[![Go Report Card](https://goreportcard.com/badge/github.com/katzenpost/hpqc)](https://goreportcard.com/report/github.com/katzenpost/hpqc)
[![CI](https://github.com/katzenpost/hpqc/actions/workflows/go.yml/badge.svg)](https://github.com/katzenpost/hpqc/actions/workflows/go.yml)



## Hybrid Post Quantum Cryptography

This library contains Golang implementations of leading quantum-resistant cryptographic primitives, popular and time-tested classical primitives, hybrid primitives that combine the strength of both, and ways to combine them all according to your needs. It also includes BACAP (blinding-and-capability) scheme, an orginal cryptographic protocol with a wide range of applications, including constructing anonymous messaging systems.

hpqc is used by the Katzenpost mixnet and published under the AGPLv3.0 licence

This library is divided into four parts:

* NIKE (non-interactive key exchange) encryption
* KEM (key encapsulation mechanism) encryption
* signature schemes
* BACAP 

NIKE  is what we usually think about when we say "Diffie-Hellman" public key exchange. It means you can find someone's public key, encrypt a message to them, and they will decrypt it with a separate private key. By contrast, KEM is a way to use symmetric-key cryptography primitives in a way that is functionally similar to public-key cryptography, by encoding the secret keys with a public key cryptography scheme that may not we suitable for universal use, but is suitable for encrypting keys. 


The key to understanding and using this cryptography library is to review the `Scheme` interfaces, for NIKE, KEM and signature schemes, as well as the BACAP API:

* NIKE Scheme: https://pkg.go.dev/github.com/katzenpost/hpqc@v0.0.44/nike#Scheme
* KEM Scheme: https://pkg.go.dev/github.com/katzenpost/hpqc@v0.0.44/kem#Scheme
* signature schemes' Scheme: https://pkg.go.dev/github.com/katzenpost/hpqc@v0.0.44/sign#Scheme
* BACAP API documentation: https://pkg.go.dev/github.com/katzenpost/hpqc@v0.0.52/bacap

Using our generic NIKE, KEM and Signature scheme interfaces helps you achieve cryptographic code agility which makes it easy to switch between cryptographic primitives.


## Using existing NIKE schemes

NIKE schemes API docs:
https://pkg.go.dev/github.com/katzenpost/hpqc/nike/schemes

NIKE interfaces docs; each NIKE implements three interfaces, Scheme, PublicKey and PrivateKey interfaces which are documented here:
https://pkg.go.dev/github.com/katzenpost/hpqc/nike


If you want to get started with one of our many existing NIKE schemes, you can reference NIKE schemes by name like so:

```golang
import (
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/nike"
)


func doCryptoStuff() {
	scheme := schemes.ByName("X25519")
	if scheme == nil {
		panic("NIKE scheme not found")
	}

	alicePubKey, alicePrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	bobPubKey, bobPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	aliceSharedSecret := scheme.DeriveSecret(alicePrivKey, bobPubKey)
	bobSharedSecret := scheme.DeriveSecret(bobPrivKey, alicePubKey)
	
	// do stuff with shared secrets.
	// aliceSharedSecret is equal to bobSharedSecret
}
```

Generic cryptographic interfaces means that if your double ratchet is already using the NIKE interfaces,
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

## Using existing KEM Schemes

KEM schemes API docs:
https://pkg.go.dev/github.com/katzenpost/hpqc/kem/schemes

KEM interfaces docs; each KEM implements three interfaces,
Scheme, PublicKey and PrivateKey interfaces which are documented here:
https://pkg.go.dev/github.com/katzenpost/hpqc/kem

If you want to get started with one of our many existing KEM
schemes, you can reference KEM schemes by name like so:

```golang
import (
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/kem"
)


func doCryptoStuff() {
	scheme := schemes.ByName("Xwing")
	if scheme == nil {
		panic("KEM scheme not found")
	}

	myPubKey, myPrivKey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}
	
	kemCiphertext, sharedSecret, err := scheme.Encapsulate(myPubKey)
	if err != nil {
		panic(err)
	}

	sharedSecret2, err := scheme.Decapsulate(myPrivKey, kemCiphertext)
	if err != nil {
		panic(err)
	}
	
	// do stuff with sharedSecret2 which is equal to sharedSecret
}
```
```golang
import "github.com/katzenpost/hpqc/kem"

func encryptMessage(publicKey kem.PublicKey, scheme kem.Scheme, message []byte) {
        ct, ss, err := scheme.Encapsulate(publicKey)
		if err != nil {
		        panic(err)
		}
		// ...
}
```


## Using existing Signature Schemes schemes

Signature schemes API docs:
https://pkg.go.dev/github.com/katzenpost/hpqc/sign/schemes

Singature interfaces docs; each signature scheme implements three interfaces,
Scheme, PublicKey and PrivateKey interfaces which are documented here:
https://pkg.go.dev/github.com/katzenpost/hpqc/sign

If you want to get started with one of our existing signature
schemes, you can reference signature schemes by name like so:

```golang
import (
	"github.com/katzenpost/hpqc/sign/schemes"
	"github.com/katzenpost/hpqc/sign"
)


func doCryptoStuff(message []byte) {
	scheme := schemes.ByName("ed25519")
	if scheme == nil {
		panic("Signature scheme not found")
	}
	
	alicePubKey, alicePrivKey := scheme.GenerateKey()
	signature := scheme.Sign(alicePrivKey, message, nil)
	
	ok := scheme.Verify(alicePubKey, message, signature, nil)
	
	if !ok {
		panic("signature verification failed!")
	}
	
	// ...
}
```

Generic hybrid signature scheme, combines any two signature schemes into one

```golang
import (
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

var Ed25519Sphincs = hybrid.New("Ed25519 Sphincs+", ed25519.Scheme(), sphincsplus.Scheme())
```

## NIKE to KEM adapter and KEM combiner

Our "NIKE to KEM adapter" uses an ad hoc hashed ElGamal construction. This construction in pseudo code is:

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

The following code demonstrates the use of both the adapter and the combiner into a hybrid KEM:

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


The [KEM Combiners paper](https://eprint.iacr.org/2018/024.pdf) makes the observation that if a KEM combiner is not security preserving then the
resulting hybrid KEM will not have IND-CCA2 security if one of the composing KEMs does not have IND-CCA2 security. Likewise the paper
points out that when using a security preserving KEM combiner, if only one of the composing KEMs has IND-CCA2 security then the resulting
hybrid KEM will have IND-CCA2 security.

Our KEM combiner uses the split PRF design for an arbitrary number of kems, here shown with only three, in pseudo code:

```
func SplitPRF(ss1, ss2, ss3, cct1, cct2, cct3 []byte) []byte {
    cct := cct1 || cct2 || cct3
    return PRF(ss1 || cct) XOR PRF(ss2 || cct) XOR PRF(ss3 || cct)
}
```


## BACAP

You can read more about BACAP  in section 4 of our paper: https://arxiv.org/abs/2501.02933

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
* X448
* CTIDH511
* CTIDH512
* CTIDH1024
* CTIDH2048
* CTIDH512-X25519
* CTIDH1024-X448
* MLKEM-768
* Xwing
* NTRUPrime (sntrup4591761)
* frodo640shake
* Kyber768-X25519
* MLKEM768-X25519
* MLKEM768-X448
* FrodoKEM-640-SHAKE-X448
* sntrup4591761-X448
* mceliece348864
* mceliece348864f
* mceliece460896
* mceliece460896f
* mceliece6688128
* mceliece6688128f
* mceliece6960119
* mceliece6960119f
* mceliece8192128
* mceliece8192128f
* mceliece348864-X25519
* mceliece348864f-X25519
* mceliece460896-X25519
* mceliece460896f-X25519
* mceliece6688128-X25519
* mceliece6688128f-X25519
* mceliece6960119-X25519
* mceliece6960119f-X25519
* mceliece8192128-X25519
* mceliece8192128f-X25519

| SIGN: Cryptographic Signature Schemes |
|:---:|
* ed25519
* ed448
* ed25519_Sphincs+shake-256f
* ed448_Sphincs+shake-256f
* ed25519_dilithium2
* ed25519_dilithium3


## Warning

This cryptography library has not had any security review.
It should be considered experimental.

## Acknowledgements

This library was inspired by Cloudflare's `circl` cryptography library.
HPQC uses the same set of interfaces as circl for signature schemes and
for KEM schemes.

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
