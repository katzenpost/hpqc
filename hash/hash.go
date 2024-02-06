package hash

import "golang.org/x/crypto/blake2b"

func Sum256(data []byte) [blake2b.Size256]byte {
	return blake2b.Sum256(data)
}
