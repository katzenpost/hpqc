//go:build !ppc64le

package hybrid

import (
	"github.com/katzenpost/hpqc/primitive/nike"
	"github.com/katzenpost/hpqc/primitive/nike/csidh"
	ecdh "github.com/katzenpost/hpqc/primitive/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
)

var NOBS_CSIDH512X25519 nike.Scheme = &scheme{
	name:   "NOBS_CSIDH-X25519",
	first:  ecdh.NewEcdhNike(rand.Reader),
	second: csidh.NOBS_CSIDH512Scheme,
}
