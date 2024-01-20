package schemes

import (
	"fmt"
	"strings"

	"github.com/katzenpost/circl/kem/frodo/frodo640shake"
	"github.com/katzenpost/circl/kem/kyber/kyber1024"
	"github.com/katzenpost/circl/kem/kyber/kyber512"
	"github.com/katzenpost/circl/kem/kyber/kyber768"
	"github.com/katzenpost/circl/kem/mceliece/mceliece348864"
	"github.com/katzenpost/circl/kem/mceliece/mceliece348864f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece460896"
	"github.com/katzenpost/circl/kem/mceliece/mceliece460896f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6688128"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6688128f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6960119"
	"github.com/katzenpost/circl/kem/mceliece/mceliece6960119f"
	"github.com/katzenpost/circl/kem/mceliece/mceliece8192128"
	"github.com/katzenpost/circl/kem/mceliece/mceliece8192128f"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/adapter"
	"github.com/katzenpost/hpqc/kem/combiner"
	"github.com/katzenpost/hpqc/kem/sntrup"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh2048"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh511"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh512"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

var allSchemes = [...]kem.Scheme{

	// classical KEM schemes

	adapter.FromNIKE(x25519.Scheme(rand.Reader)),

	// post quantum KEM schemes

	kyber512.Scheme(),
	kyber768.Scheme(),
	kyber1024.Scheme(),
	frodo640shake.Scheme(),
	mceliece348864.Scheme(),
	mceliece348864f.Scheme(),
	mceliece460896.Scheme(),
	mceliece460896f.Scheme(),
	mceliece6688128.Scheme(),
	mceliece6688128f.Scheme(),
	mceliece6960119.Scheme(),
	mceliece6960119f.Scheme(),
	mceliece8192128.Scheme(),
	mceliece8192128f.Scheme(),

	// post quantum KEM schemes
	// ...but converted using an
	// ad hoc hash ElGamal construction
	adapter.FromNIKE(ctidh511.Scheme()),
	adapter.FromNIKE(ctidh512.Scheme()),
	adapter.FromNIKE(ctidh1024.Scheme()),
	adapter.FromNIKE(ctidh2048.Scheme()),

	// hybrid KEM schemes

	combiner.New(
		"Kyber768-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			kyber768.Scheme(),
		},
	),

	combiner.New(
		"sntrup4591761-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			sntrup.Scheme(),
		},
	),

	combiner.New(
		"ctidh511-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			adapter.FromNIKE(ctidh511.Scheme()),
		},
	),

	combiner.New(
		"ctidh512-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			adapter.FromNIKE(ctidh512.Scheme()),
		},
	),

	combiner.New(
		"ctidh1024-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			adapter.FromNIKE(ctidh1024.Scheme()),
		},
	),

	combiner.New(
		"ctidh2048-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			adapter.FromNIKE(ctidh2048.Scheme()),
		},
	),

	// hybrid KEM schemes with two post quantum KEMs

	combiner.New(
		"X25519-Kyber768-sntrup4591761",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			kyber768.Scheme(),
			sntrup.Scheme(),
		},
	),

	combiner.New(
		"X25519-kyber768-ctidh511",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			kyber768.Scheme(),
			adapter.FromNIKE(ctidh511.Scheme()),
		},
	),

	combiner.New(
		"X25519-kyber768-ctidh512",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			kyber768.Scheme(),
			adapter.FromNIKE(ctidh512.Scheme()),
		},
	),

	combiner.New(
		"X25519-kyber1024-ctidh1024",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			kyber1024.Scheme(),
			adapter.FromNIKE(ctidh1024.Scheme()),
		},
	),

	// "the CTIDH hybrid sledge hammer"
	combiner.New(
		"X25519-ctidh511-ctidh512-ctidh1024-ctidh2048",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			adapter.FromNIKE(ctidh511.Scheme()),
			adapter.FromNIKE(ctidh512.Scheme()),
			adapter.FromNIKE(ctidh1024.Scheme()),
			adapter.FromNIKE(ctidh2048.Scheme()),
		},
	),

	// another sledge hammer KEM just to show that we can if we want to
	combiner.New(
		"X25519-ctidh1024-sntrup4591761-mceliece8192128f-frodo640shake-kyber1024",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			adapter.FromNIKE(ctidh1024.Scheme()),
			sntrup.Scheme(),
			mceliece8192128f.Scheme(),
			frodo640shake.Scheme(),
			kyber1024.Scheme(),
		},
	),
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the NIKE scheme by string name.
func ByName(name string) kem.Scheme {
	ret := allSchemeNames[strings.ToLower(name)]
	if ret == nil {
		panic(fmt.Sprintf("no such name as %s\n", name))
	}
	return ret
}

// All returns all NIKE schemes supported.
func All() []kem.Scheme {
	a := allSchemes
	return a[:]
}
