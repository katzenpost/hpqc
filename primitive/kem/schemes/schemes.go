package schemes

import (
	"fmt"
	"strings"

	"github.com/katzenpost/circl/kem/kyber/kyber768"
	"github.com/katzenpost/hpqc/primitive/kem"
	"github.com/katzenpost/hpqc/primitive/kem/adapter"
	"github.com/katzenpost/hpqc/primitive/kem/combiner"
	kemhybrid "github.com/katzenpost/hpqc/primitive/kem/hybrid"
	"github.com/katzenpost/hpqc/primitive/kem/sntrup"
	"github.com/katzenpost/hpqc/primitive/nike/x25519"
	ecdh "github.com/katzenpost/hpqc/primitive/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

var allSchemes = [...]kem.Scheme{
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
		"Kyber768_X25519",
		adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
		kyber768.Scheme(),
	),

	combiner.New(
		"sntrup4591761_Kyber768_X25519",
		[]kem.Scheme{
			adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
			kyber768.Scheme(),
			sntrup.Scheme(),
		},
	),

	kemhybrid.New(
		"sntrup4591761_X25519",
		adapter.FromNIKE(ecdh.Scheme(rand.Reader)),
		sntrup.Scheme(),
	),
	combiner.New(
		"sntrup4591761_X25519_combiner", // used for testing
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			sntrup.Scheme(),
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
