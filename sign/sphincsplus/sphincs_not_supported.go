//go:build !darwin || !linux

package sphincsplus

import "github.com/katzenpost/hpqc/sign"

func Scheme() sign.Scheme {
	return nil
}
