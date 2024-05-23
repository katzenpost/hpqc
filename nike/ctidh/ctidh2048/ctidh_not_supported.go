//go:build (windows && arm64) || (darwin && arm64)
// +build windows,arm64 darwin,arm64

// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package ctidh2048

import "github.com/katzenpost/hpqc/nike"

func Scheme() nike.Scheme { return nil }
