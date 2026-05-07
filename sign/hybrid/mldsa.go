// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/mldsa"
)

// MLDSA44Ed25519 is the hybrid of ML-DSA-44 and Ed25519.
var MLDSA44Ed25519 = New("ML-DSA-44-Ed25519", mldsa.Scheme44(), ed25519.Scheme())

// MLDSA65Ed25519 is the hybrid of ML-DSA-65 and Ed25519.
var MLDSA65Ed25519 = New("ML-DSA-65-Ed25519", mldsa.Scheme65(), ed25519.Scheme())

// MLDSA87Ed25519 is the hybrid of ML-DSA-87 and Ed25519.
var MLDSA87Ed25519 = New("ML-DSA-87-Ed25519", mldsa.Scheme87(), ed25519.Scheme())
