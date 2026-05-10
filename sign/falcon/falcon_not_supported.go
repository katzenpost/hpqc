//go:build windows

// SPDX-FileCopyrightText: (c) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package falcon

import "github.com/katzenpost/hpqc/sign"

// SchemePadded512 returns nil on Windows, where the upstream cgo Falcon
// implementation is not built.
func SchemePadded512() sign.Scheme { return nil }

// SchemePadded1024 returns nil on Windows, where the upstream cgo
// Falcon implementation is not built.
func SchemePadded1024() sign.Scheme { return nil }
