"""Pruebas de gestión de claves."""

from __future__ import annotations

import os

import pytest

from cryptoagility.exceptions import KeyFileError
from cryptoagility.key_manager import (
    encode_key,
    generate_key,
    key_file_permissions_too_open,
    load_key,
    save_key,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="Permisos POSIX")


def test_generate_key_size_and_uniqueness():
    keys = {generate_key() for _ in range(100)}
    assert len(keys) == 100
    assert all(len(k) == 32 for k in keys)


def test_generate_key_rejects_tiny_sizes():
    with pytest.raises(ValueError):
        generate_key(8)


def test_save_and_load_roundtrip(tmp_path, key):
    path = save_key(key, tmp_path / "k.key")
    assert load_key(path) == key
    assert load_key(path, expected_size=32) == key


def test_key_file_is_text_base64_and_not_raw(tmp_path, key):
    path = save_key(key, tmp_path / "k.key")
    content = path.read_bytes()
    assert content.strip().decode("ascii") == encode_key(key)
    assert key not in content


def test_save_creates_parent_directories(tmp_path, key):
    path = save_key(key, tmp_path / "a" / "b" / "k.key")
    assert path.is_file()


def test_save_refuses_to_overwrite(tmp_path, key, other_key):
    path = save_key(key, tmp_path / "k.key")
    with pytest.raises(KeyFileError, match="ya existe"):
        save_key(other_key, path)
    assert load_key(path) == key  # intacta


def test_save_overwrite_when_forced(tmp_path, key, other_key):
    path = save_key(key, tmp_path / "k.key")
    save_key(other_key, path, overwrite=True)
    assert load_key(path) == other_key


@posix_only
def test_key_file_permissions_are_0600(tmp_path, key):
    path = save_key(key, tmp_path / "k.key")
    assert (path.stat().st_mode & 0o777) == 0o600
    assert not key_file_permissions_too_open(path)


@posix_only
def test_detects_open_permissions(tmp_path, key):
    path = save_key(key, tmp_path / "k.key")
    path.chmod(0o644)
    assert key_file_permissions_too_open(path)


def test_load_missing_file(tmp_path):
    with pytest.raises(KeyFileError, match="No se encontró"):
        load_key(tmp_path / "nope.key")


def test_load_directory(tmp_path):
    with pytest.raises(KeyFileError):
        load_key(tmp_path)


def test_load_empty_file(tmp_path):
    path = tmp_path / "empty.key"
    path.write_bytes(b"\n")
    with pytest.raises(KeyFileError, match="vacío"):
        load_key(path)


def test_load_invalid_base64_does_not_leak_content(tmp_path):
    path = tmp_path / "bad.key"
    path.write_text("CONTENIDO-SECRETO-NO-BASE64!!!")
    with pytest.raises(KeyFileError) as exc:
        load_key(path)
    assert "SECRETO" not in str(exc.value)


def test_load_wrong_size(tmp_path):
    path = save_key(generate_key(16), tmp_path / "short.key")
    with pytest.raises(KeyFileError, match="esperaban 32"):
        load_key(path, expected_size=32)


def test_load_oversized_file(tmp_path):
    path = tmp_path / "huge.key"
    path.write_bytes(b"A" * 10_000)
    with pytest.raises(KeyFileError, match="grande"):
        load_key(path)
