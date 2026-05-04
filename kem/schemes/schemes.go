package schemes

import (
	"strings"

	"github.com/katzenpost/circl/kem/frodo/frodo640shake"
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
	"github.com/katzenpost/hpqc/kem/circlkem"
	"github.com/katzenpost/hpqc/kem/combiner"
	"github.com/katzenpost/hpqc/kem/hybrid"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/kem/sntrup"
	"github.com/katzenpost/hpqc/kem/xwing"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh1024"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh2048"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh511"
	"github.com/katzenpost/hpqc/nike/ctidh/ctidh512"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/nike/x448"
	"github.com/katzenpost/hpqc/rand"
)

// mustCombine wraps combiner.New for the registry's package-level slice
// initialisation. A nil sub-scheme is a programmer error here, so we
// turn the error into a panic at start-up.
func mustCombine(name string, schemes []kem.Scheme) kem.Scheme {
	s, err := combiner.New(name, schemes)
	if err != nil {
		panic(err)
	}
	return s
}

var potentialSchemes = [...]kem.Scheme{

	// PQ KEMs

	adapter.FromNIKE(ctidh511.Scheme()),
	adapter.FromNIKE(ctidh512.Scheme()),
	adapter.FromNIKE(ctidh1024.Scheme()),
	adapter.FromNIKE(ctidh2048.Scheme()),

	// hybrid KEMs

	mustCombine(
		"CTIDH512-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(ctidh512.Scheme()),
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
		},
	),
	mustCombine(
		"CTIDH1024-X448",
		[]kem.Scheme{
			adapter.FromNIKE(ctidh1024.Scheme()),
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
		},
	),
}

var allSchemes = []kem.Scheme{

	// classical KEM schemes (converted from NIKE via hashed elgamal construction)

	// Classical DiffieHellman imeplementation has a bug with this ticket:
	// https://github.com/katzenpost/hpqc/issues/39
	//adapter.FromNIKE(diffiehellman.Scheme()),

	adapter.FromNIKE(x25519.Scheme(rand.Reader)),
	adapter.FromNIKE(x448.Scheme(rand.Reader)),

	// post quantum KEM schemes

	mlkem768.Scheme(),
	sntrup.Scheme(),
	circlkem.FromCircl(frodo640shake.Scheme()),
	circlkem.FromCircl(mceliece348864.Scheme()),
	circlkem.FromCircl(mceliece348864f.Scheme()),
	circlkem.FromCircl(mceliece460896.Scheme()),
	circlkem.FromCircl(mceliece460896f.Scheme()),
	circlkem.FromCircl(mceliece6688128.Scheme()),
	circlkem.FromCircl(mceliece6688128f.Scheme()),
	circlkem.FromCircl(mceliece6960119.Scheme()),
	circlkem.FromCircl(mceliece6960119f.Scheme()),
	circlkem.FromCircl(mceliece8192128.Scheme()),
	circlkem.FromCircl(mceliece8192128f.Scheme()),

	// hybrid KEM schemes

	xwing.Scheme(),

	// XXX TODO: must soon deprecate use of "hybrid.New" in favour of "combiner.New".
	// We'd also like to remove Kyber now that we have mlkem768.
	hybrid.New(
		"Kyber768-X25519",
		adapter.FromNIKE(x25519.Scheme(rand.Reader)),
		circlkem.FromCircl(kyber768.Scheme()),
	),

	// If Xwing is not the PQ Hybrid KEM you are looking for then we recommend
	// using our secure generic KEM combiner:
	mustCombine(
		"MLKEM768-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mlkem768.Scheme(),
		},
	),
	mustCombine(
		"MLKEM768-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			mlkem768.Scheme(),
		},
	),

	mustCombine(
		"FrodoKEM-640-SHAKE-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			circlkem.FromCircl(frodo640shake.Scheme()),
		},
	),
	mustCombine(
		"sntrup4591761-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			sntrup.Scheme(),
		},
	),

	// all the Classic McEliece's from our fork of circl
	mustCombine(
		"mceliece348864-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece348864.Scheme()),
		},
	),
	mustCombine(
		"mceliece348864f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece348864f.Scheme()),
		},
	),
	mustCombine(
		"mceliece460896-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece460896.Scheme()),
		},
	),
	mustCombine(
		"mceliece460896f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece460896f.Scheme()),
		},
	),
	mustCombine(
		"mceliece6688128-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece6688128.Scheme()),
		},
	),
	mustCombine(
		"mceliece6688128f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece6688128f.Scheme()),
		},
	),
	mustCombine(
		"mceliece6960119-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece6960119.Scheme()),
		},
	),
	mustCombine(
		"mceliece6960119f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece6960119f.Scheme()),
		},
	),
	mustCombine(
		"mceliece8192128-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece8192128.Scheme()),
		},
	),
	mustCombine(
		"mceliece8192128f-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			circlkem.FromCircl(mceliece8192128f.Scheme()),
		},
	),
}

var allSchemeNames map[string]kem.Scheme

func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	for _, scheme := range potentialSchemes {
		if scheme != nil {
			allSchemes = append(allSchemes, scheme)
		}
	}
	for _, scheme := range allSchemes {
		allSchemeNames[strings.ToLower(scheme.Name())] = scheme
	}
}

// ByName returns the NIKE scheme by string name.
func ByName(name string) kem.Scheme {
	ret := allSchemeNames[strings.ToLower(name)]
	return ret
}

// All returns all NIKE schemes supported.
func All() []kem.Scheme {
	a := allSchemes
	return a[:]
}
