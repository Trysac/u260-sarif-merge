"""Behavior tests for the public API of sarif_merge."""

from __future__ import annotations

import pytest

import sarif_merge


def test_normalize_trims_and_lowercases() -> None:
    assert sarif_merge.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        sarif_merge.normalize(value)


def test_version_is_semver() -> None:
    parts = sarif_merge.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
