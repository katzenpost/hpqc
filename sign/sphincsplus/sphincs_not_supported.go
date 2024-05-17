//go:build !linux && !darwin

package sphincsplus

import "github.com/katzenpost/hpqc/sign"

func Scheme() sign.Scheme {
	return nil
}
