// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/sqisign"
)

// SQIsignLvl1Ed25519 is the hybrid of SQIsign level 1 and Ed25519.
// Signatures and public keys are the simple concatenation of the two
// component schemes, in that order.
var SQIsignLvl1Ed25519 = New("SQIsign-lvl1-Ed25519", sqisign.Scheme(), ed25519.Scheme())
