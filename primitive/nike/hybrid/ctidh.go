//go:build ctidh
// +build ctidh

package hybrid

import (
	"github.com/katzenpost/hpqc/primitive/nike"
	"github.com/katzenpost/hpqc/primitive/nike/ctidh"
	"github.com/katzenpost/hpqc/primitive/nike/ecdh"
	"github.com/katzenpost/hpqc/rand"
)

var CTIDH1024X25519 nike.Scheme = &scheme{
	name:   "CTIDH1024-X25519",
	first:  ctidh.CTIDH1024Scheme,
	second: ecdh.NewEcdhNike(rand.Reader),
}
