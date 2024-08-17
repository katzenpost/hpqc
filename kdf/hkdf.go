package kdf

import (
	"hash"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

func HKDF(ikm, salt []byte) []byte {
	h := func() hash.Hash {
		h, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return h
	}
	return hkdf.Extract(h, ikm, salt)
}
