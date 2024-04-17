package schemes

import (
	"bytes"
	"testing"

	"github.com/katzenpost/hpqc/kem"
)

func BenchmarkKeyGen(b *testing.B) {
	var pubkey kem.PublicKey
	var privkey kem.PrivateKey
	var err error

	schemes := All()

	for _, s := range schemes {
		b.Run(s.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				pubkey, privkey, err = s.GenerateKeyPair()
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

	pubkey.Scheme()
	privkey.Scheme()
}

func BenchmarkEncap(b *testing.B) {
	schemes := All()

	for _, s := range schemes {
		pubkey, _, err := s.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}

		var ct []byte
		var ss []byte

		b.Run(s.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ct, ss, err = s.Encapsulate(pubkey)
				if err != nil {
					b.Fatal(err)
				}
			}
		})

		ct2 := make([]byte, len(ct))
		copy(ct2, ct)

		ss2 := make([]byte, len(ss))
		copy(ss2, ss)
	}

}

func BenchmarkDecaps(b *testing.B) {
	schemes := All()

	for _, s := range schemes {
		pubkey, privkey, err := s.GenerateKeyPair()
		if err != nil {
			b.Fatal(err)
		}

		ct, ss, err := s.Encapsulate(pubkey)
		if err != nil {
			b.Fatal(err)
		}

		b.Run(s.Name(), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ss2, err := s.Decapsulate(privkey, ct)
				if err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(ss, ss2) {
					b.Fatal("decapsulated shared secret mismatch error")
				}
			}
		})

		ct2 := make([]byte, len(ct))
		copy(ct2, ct)

		ss2 := make([]byte, len(ss))
		copy(ss2, ss)
	}
}
