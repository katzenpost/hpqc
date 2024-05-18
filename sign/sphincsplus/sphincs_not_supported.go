//go:build (darwin && !amd64) || (linux && !amd64) || (!linux && !darwin)

package sphincsplus

import "github.com/katzenpost/hpqc/sign"

func Scheme() sign.Scheme {
	return nil
}
