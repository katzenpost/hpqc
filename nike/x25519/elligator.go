// SPDX-FileCopyrightText: © 2023 David Stainton and Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

package x25519

//#include "monocypher.h"
import "C"
import "unsafe"

const keySize = 32

func Unelligator(hidden []byte) []byte {
	curve := make([]byte, 32)
	C.crypto_elligator_map((*C.uint8_t)(unsafe.Pointer(&curve[0])), (*C.uint8_t)(unsafe.Pointer(&hidden[0])))
	return curve
}

func GenerateHiddenKeyPair(seed *[32]byte) ([]byte, []byte) {
	pk := make([]byte, keySize)
	sk := make([]byte, keySize)
	C.crypto_elligator_key_pair((*C.uint8_t)(unsafe.Pointer(&pk[0])),
		(*C.uint8_t)(unsafe.Pointer(&sk[0])),
		(*C.uint8_t)(unsafe.Pointer(&seed[0])))
	return pk, sk
}
