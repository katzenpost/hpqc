//go:build ppc64le

package hybrid

import (
	"github.com/katzenpost/hpqc/primitive/nike"
	"github.com/katzenpost/hpqc/primitive/nike/ecdh"
	"github.com/katzenpost/hpqc/rand"
)

var NOBS_CSIDH512X25519 nike.Scheme = &scheme{
	name:   "NOBS_CSIDH-X25519",
	first:  ecdh.NewEcdhNike(rand.Reader),
	second: nil,
}
