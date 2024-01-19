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
	kemhybrid "github.com/katzenpost/hpqc/kem/hybrid"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

var allSchemes = [...]kem.Scheme{
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

	adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
	// Must build with `ctidh` build tag (and other supporting env vars)
	// for CTIDH usage:
	// adapter.FromNIKE(hybrid.CTIDH1024X25519),
	//kemhybrid.New(
	//	"Kyber1024-CTIDH1024-X25519",
	//	adapter.FromNIKE(hybrid.CTIDH1024X25519),
	//	kyber1024.Scheme(),
	//),

	kemhybrid.New(
		"Kyber768-X25519",
		adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
		kyber768.Scheme(),
	),

	/*
		combiner.New(
			"sntrup4591761-Kyber768-X25519",
			[]kem.Scheme{
				adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
				kyber768.Scheme(),
				sntrup.Scheme(),
			},
		),

		kemhybrid.New(
			"sntrup4591761-X25519",
			adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
			sntrup.Scheme(),
		),
		combiner.New(
			"sntrup4591761-X25519-combiner", // used for testing
			[]kem.Scheme{
				adapter.FromNIKE(x25519.Scheme(rand.Reader)),
				sntrup.Scheme(),
			},
		),
	*/
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
