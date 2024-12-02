package schemes

import (
	"fmt"
	"log"
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

// Group schemes into logical categories
var classicalSchemes = []kem.Scheme{
	adapter.FromNIKE(x25519.Scheme(rand.Reader)),
	adapter.FromNIKE(x448.Scheme(rand.Reader)),
}

var postQuantumSchemes = []kem.Scheme{
	mlkem768.Scheme(),
	sntrup.Scheme(),
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
}

var hybridSchemes = []kem.Scheme{
	combiner.New(
		"MLKEM768-X25519",
		[]kem.Scheme{
			adapter.FromNIKE(x25519.Scheme(rand.Reader)),
			mlkem768.Scheme(),
		},
	),
	combiner.New(
		"MLKEM768-X448",
		[]kem.Scheme{
			adapter.FromNIKE(x448.Scheme(rand.Reader)),
			mlkem768.Scheme(),
		},
	),
}

// Collect all schemes together
var allSchemes []kem.Scheme
var allSchemeNames map[string]kem.Scheme

// Initialize all schemes and validate them
func init() {
	allSchemeNames = make(map[string]kem.Scheme)
	allSchemes = append(allSchemes, classicalSchemes...)
	allSchemes = append(allSchemes, postQuantumSchemes...)
	allSchemes = append(allSchemes, hybridSchemes...)

	for _, scheme := range allSchemes {
		if err := validateScheme(scheme); err == nil {
			allSchemeNames[strings.ToLower(scheme.Name())] = scheme
		} else {
			log.Printf("Warning: %v", err)
		}
	}
}

// Validate a scheme to ensure it is not nil and has a valid name
func validateScheme(scheme kem.Scheme) error {
	if scheme == nil || strings.TrimSpace(scheme.Name()) == "" {
		return fmt.Errorf("invalid scheme: %v", scheme)
	}
	return nil
}

// ByName retrieves a scheme by name, returning an error if not found
func ByName(name string) (kem.Scheme, error) {
	scheme, ok := allSchemeNames[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("scheme '%s' not found", name)
	}
	return scheme, nil
}

// All returns a slice of all supported schemes
func All() []kem.Scheme {
	return allSchemes
}
