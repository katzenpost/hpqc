package aead

// #include "monocypher.h"
// #include "sha512.h"
// #include <stdio.h>
// #include <stdlib.h>
import "C"

import "unsafe"

/*
MIT License

Copyright (c) 2017 demonshreder

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// AeadLock is the same as Lock() but allows some additional data to be signed
// though not encrypted with the rest. AeadLock returns mac, ciphertext and the
// authenticated text.
func AeadLock(plaintext, nonce, key, addData []byte) (mac, ciphertext, data []byte) {
	// void crypto_aead_lock(uint8_t        mac[16],
	// uint8_t       *ciphertext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t *ad       , size_t ad_size,
	// const uint8_t *plaintext, size_t text_size);

	CAdDataSize := (C.size_t)(len(addData))
	CAdData := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(addData))))
	defer C.free(unsafe.Pointer(CAdData))
	CTextSize := (C.size_t)(len(plaintext))
	CPlain := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(plaintext))))
	defer C.free(unsafe.Pointer(CPlain))
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(CKey))
	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(CNonce))
	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 16))))
	defer C.free(unsafe.Pointer(CMac))
	CCipher := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(plaintext)))))
	defer C.free(unsafe.Pointer(CCipher))
	//	C Method call
	C.crypto_aead_lock(CMac, CCipher, CKey, CNonce, CAdData, CAdDataSize, CPlain, CTextSize)
	// Converting CTypes back to Go
	var GCipherText []byte = C.GoBytes(unsafe.Pointer(CCipher), C.int(len(plaintext)))
	var GMac []byte = C.GoBytes(unsafe.Pointer(CMac), C.int(16))
	var GAdData []byte = C.GoBytes(unsafe.Pointer(CAdData), C.int(CAdDataSize))
	return GMac, GCipherText, GAdData
}

// AeadUnlock is the same as Unlock(), but checks authenticated
// data and returns the deciphered plaintext.
func AeadUnlock(ciphertext, nonce, key, mac, addData []byte) (plaintext []byte) {
	// int crypto_aead_unlock(uint8_t       *plaintext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t  mac[16],
	// const uint8_t *ad        , size_t ad_size,
	// const uint8_t *ciphertext, size_t text_size);

	CAdDataSize := (C.size_t)(len(addData))
	CAdData := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(addData))))
	defer C.free(unsafe.Pointer(CAdData))
	CCipherSize := (C.size_t)(len(ciphertext))
	CCipherText := (*C.uint8_t)(unsafe.Pointer(C.CBytes(ciphertext)))
	defer C.free(unsafe.Pointer(CCipherText))
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(CKey))
	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(CNonce))
	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes(mac)))
	defer C.free(unsafe.Pointer(CMac))
	CPlainText := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(ciphertext)))))
	defer C.free(unsafe.Pointer(CPlainText))
	//	C Method call
	C.crypto_aead_unlock(CPlainText, CKey, CNonce, CMac, CAdData, CAdDataSize, CCipherText, CCipherSize)
	// Converting CTypes back to Go
	var GPlainText []byte = C.GoBytes(unsafe.Pointer(CPlainText), C.int(len(ciphertext)))
	// return Nmac, Ncipher

	return GPlainText
}
