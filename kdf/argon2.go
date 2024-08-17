package kdf

import (
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
)

func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.Key(password, salt, time, memory, threads, keyLen)
}

func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

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
