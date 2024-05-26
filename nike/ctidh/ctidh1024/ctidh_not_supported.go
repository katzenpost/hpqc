//go:build windows || darwin

// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package ctidh1024

import "github.com/katzenpost/hpqc/nike"

func Scheme() nike.Scheme { return nil }
