// SPDX-License-Identifier: AGPL-3.0-only

package mlkem768

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
)

type wycheproofMLKEM768File struct {
	NumberOfTests int `json:"numberOfTests"`
	TestGroups    []struct {
		Tests []struct {
			TcID   int    `json:"tcId"`
			Seed   string `json:"seed"`
			Ek     string `json:"ek"`
			C      string `json:"c"`
			K      string `json:"K"`
			Result string `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func TestWycheproof(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("testdata", "mlkem_768_test.json"))
	require.NoError(t, err)
	var vectors wycheproofMLKEM768File
	require.NoError(t, json.Unmarshal(raw, &vectors))

	decode := func(value string) []byte {
		decoded, err := hex.DecodeString(value)
		require.NoError(t, err)
		return decoded
	}
	scheme := Scheme()
	caseCount := 0
	for _, group := range vectors.TestGroups {
		for _, tc := range group.Tests {
			caseCount++
			seed := decode(tc.Seed)
			if len(seed) != scheme.SeedSize() {
				require.PanicsWithValue(t, kem.ErrSeedSize, func() { scheme.DeriveKeyPair(seed) }, "tcId %d", tc.TcID)
				switch tc.Result {
				case "invalid", "acceptable":
					continue
				case "valid":
					require.FailNow(t, "valid vector has an invalid seed size", "tcId %d", tc.TcID)
				default:
					require.FailNow(t, "unknown Wycheproof result", "tcId %d: %s", tc.TcID, tc.Result)
				}
			}
			pub, priv := scheme.DeriveKeyPair(seed)
			if tc.Ek != "" {
				got, err := pub.MarshalBinary()
				require.NoError(t, err, "tcId %d", tc.TcID)
				require.Equal(t, decode(tc.Ek), got, "tcId %d", tc.TcID)
			}

			got, err := scheme.Decapsulate(priv, decode(tc.C))
			switch tc.Result {
			case "valid":
				require.NoError(t, err, "tcId %d", tc.TcID)
				require.Equal(t, decode(tc.K), got, "tcId %d", tc.TcID)
			case "invalid":
				require.Error(t, err, "tcId %d", tc.TcID)
			case "acceptable":
				if err == nil {
					require.Equal(t, decode(tc.K), got, "tcId %d", tc.TcID)
				}
			default:
				require.FailNow(t, "unknown Wycheproof result", "tcId %d: %s", tc.TcID, tc.Result)
			}
		}
	}
	require.Equal(t, vectors.NumberOfTests, caseCount)
}
