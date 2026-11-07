# Using hpqc from Go

How to look schemes up by name and compose them. Back to the
[README](../README.md). API documentation is on
[pkg.go.dev](https://pkg.go.dev/github.com/katzenpost/hpqc); every scheme name
is in [schemes.md](schemes.md). The examples below leave out error checks to
stay short; [examples/](../examples) has two complete programs that pair a NIKE or
a KEM with a symmetric cipher.

## NIKE

```go
import "github.com/katzenpost/hpqc/nike/schemes"

scheme := schemes.ByName("X25519")
alicePub, alicePriv, err := scheme.GenerateKeyPair()
bobPub, bobPriv, err := scheme.GenerateKeyPair()

aliceSecret := scheme.DeriveSecret(alicePriv, bobPub)
bobSecret := scheme.DeriveSecret(bobPriv, alicePub) // equal to aliceSecret
```

Code written against `nike.Scheme`, such as a double ratchet, moves to a
post-quantum hybrid by changing the name, for example to `X25519-CTIDH1024`
(also `hybrid.X25519CTIDH1024` in `nike/hybrid`).

## KEM

```go
import "github.com/katzenpost/hpqc/kem/schemes"

scheme := schemes.ByName("XWING")
pub, priv, err := scheme.GenerateKeyPair()

ct, secret, err := scheme.Encapsulate(pub)
secret2, err := scheme.Decapsulate(priv, ct) // equal to secret
```

## Signatures

```go
import "github.com/katzenpost/hpqc/sign/schemes"

scheme := schemes.ByName("Ed25519")
pub, priv, err := scheme.GenerateKey()

sig := scheme.Sign(priv, message, nil)
ok := scheme.Verify(pub, message, sig, nil)
```

`sign/hybrid` combines any two signature schemes into one:

```go
import (
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/hybrid"
	"github.com/katzenpost/hpqc/sign/sphincsplus"
)

var Ed25519Sphincs = hybrid.New("Ed25519-Sphincs+", ed25519.Scheme(), sphincsplus.Scheme())
```

## Composing a hybrid KEM

The NIKE to KEM adapter and the KEM combiner
([constructions.md](constructions.md)) build a hybrid from any NIKEs and KEMs:

```go
import (
	"github.com/katzenpost/circl/kem/frodo/frodo640shake"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/circlkem"
	"github.com/katzenpost/hpqc/kem/combiner"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/rand"
)

scheme, err := combiner.New(
	"MLKEM768-Frodo640Shake-CTIDH1024-X448",
	[]kem.Scheme{
		mlkem768.Scheme(),
		circlkem.FromCircl(frodo640shake.Scheme()),
		adapter.FromNIKE(ctidh1024.Scheme()),
		adapter.FromNIKE(x448.Scheme(rand.Reader)),
	},
)
```
