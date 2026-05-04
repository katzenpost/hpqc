# SPDX-FileCopyrightText: © 2026 David Stainton
# SPDX-License-Identifier: AGPL-3.0-only
"""hpqc.kem — key encapsulation mechanisms.

Currently exposes the multi-recipient KEM construction at
``hpqc.kem.mkem``, which lifts any NIKE scheme into an MKEM that
encapsulates a single payload to one or many recipients.
"""
