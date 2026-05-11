// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package hybrid

import (
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/hpqc/sign/falcon"
)

// FalconPadded512Ed25519 is the hybrid of Falcon-padded-512 and Ed25519.
var FalconPadded512Ed25519 = New("Falcon-padded-512-Ed25519", falcon.SchemePadded512(), ed25519.Scheme())

// FalconPadded1024Ed25519 is the hybrid of Falcon-padded-1024 and Ed25519.
var FalconPadded1024Ed25519 = New("Falcon-padded-1024-Ed25519", falcon.SchemePadded1024(), ed25519.Scheme())
