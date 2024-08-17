package kdf

import (
	"golang.org/x/crypto/argon2"
)

func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.Key(password, salt, time, memory, threads, keyLen)
}

func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}
