// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The committed BACAP vector files are what inputs.json generates. The
// comparison is on JSON values, the rule the Python and Lean generators are
// held to as well.
func TestBACAPVectorsMatchInputs(t *testing.T) {
	root := filepath.Join("..", "..")
	files := genBACAPFiles(loadBACAPInputs(filepath.Join(root, "bacap", "inputs.json")))
	for _, name := range bacapFileOrder {
		t.Run(name, func(t *testing.T) {
			gen, err := json.Marshal(files[name])
			if err != nil {
				t.Fatal(err)
			}
			committed, err := os.ReadFile(filepath.Join(root, "bacap", name+".json"))
			if err != nil {
				t.Fatal(err)
			}
			var a, b any
			if err := json.Unmarshal(gen, &a); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(committed, &b); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(a, b) {
				t.Fatalf("%s.json differs from what inputs.json generates; run go run ./testvectors/cmd/generate", name)
			}
		})
	}
}
