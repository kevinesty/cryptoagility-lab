"""Fixtures compartidas. Todas las claves son aleatorias y efímeras: no hay secretos reales."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest


@pytest.fixture
def key() -> bytes:
    """Clave AES-256 aleatoria generada por prueba."""
    return secrets.token_bytes(32)


@pytest.fixture
def other_key() -> bytes:
    """Una segunda clave distinta, para pruebas de clave incorrecta."""
    return secrets.token_bytes(32)


@pytest.fixture
def sample_bytes() -> bytes:
    return b"Informacion confidencial de prueba. " * 20  # 720 bytes


@pytest.fixture
def plain_file(tmp_path: Path, sample_bytes: bytes) -> Path:
    path = tmp_path / "documento.txt"
    path.write_bytes(sample_bytes)
    return path
