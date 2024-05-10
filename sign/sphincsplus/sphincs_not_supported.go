//go:build (!darwin || !linux) && !amd64

package p

import "github.com/katzenpost/hpqc/sign"

func Scheme() sign.Scheme {
	return nil
}
