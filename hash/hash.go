package hash

import (
	"encoding"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

const HashSize = blake2b.Size256

func Sum256(data []byte) [HashSize]byte {
	return blake2b.Sum256(data)
}

func Sum256From(key encoding.BinaryMarshaler) ([HashSize]byte, error) {
	var zero [HashSize]byte // Return value in case of error

	blob, err := key.MarshalBinary()
	if err != nil {
		return zero, fmt.Errorf("failed to marshal binary: %w", err)
	}
	return blake2b.Sum256(blob), nil
}
