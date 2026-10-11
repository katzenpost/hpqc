# SPDX-License-Identifier: AGPL-3.0-only
"""The vector corpus drives encrypt_for_context with an empty plaintext.

encrypt_for_context refuses that below cryptography 45, where AESGCMSIV
cannot take zero-length data, so those vectors and the generator that
builds them cannot run there. The refusal itself is asserted on every
version by tests/bacap/test_empty_box_floor.py, so nothing goes
unchecked.
"""

from __future__ import annotations

import pytest

from hpqc.bacap.stateless import _CRYPTOGRAPHY, _EMPTY_AEAD_FROM

REASON = (
    "the vector drives encrypt_for_context with an empty plaintext, "
    "which it refuses below cryptography 45"
)


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    if _CRYPTOGRAPHY >= _EMPTY_AEAD_FROM:
        return
    skip = pytest.mark.skip(reason=REASON)
    for item in items:
        empty = "encrypt_empty_plaintext" in item.name
        generator = "test_gen_vectors.py" in item.nodeid
        if empty or generator:
            item.add_marker(skip)
