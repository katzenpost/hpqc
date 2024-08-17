package prp

import (
	"crypto/aes"
)

const KeySize = 32

func AeadEcbEncrypt(key, mesg *[KeySize]byte) *[KeySize]byte {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	src := make([]byte, KeySize)
	dst := &[KeySize]byte{}
	cipher.Encrypt(dst[:], src)
	return dst
}

func AeadEcbDecrypt(key, ct *[KeySize]byte) *[KeySize]byte {
	cipher, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	src := make([]byte, KeySize)
	dst := &[KeySize]byte{}
	cipher.Decrypt(dst[:], src)
	return dst
}
