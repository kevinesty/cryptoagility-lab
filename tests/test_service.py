"""Pruebas del servicio de archivos: cifrado, descifrado e inspección."""

from __future__ import annotations

import secrets
from pathlib import Path

import pytest

from cryptoagility import service
from cryptoagility.exceptions import (
    AuthenticationError,
    FileOperationError,
    InvalidFileFormatError,
    InvalidKeyError,
    UnsupportedAlgorithmError,
    UnsupportedVersionError,
)
from cryptoagility.file_format import FIXED_HEADER_SIZE
from cryptoagility.service import decrypt_file, encrypt_file, inspect_file

NONCE_OFFSET = FIXED_HEADER_SIZE  # el nonce empieza justo tras los 7 bytes fijos
CIPHERTEXT_OFFSET = FIXED_HEADER_SIZE + 12


def _listing(directory: Path) -> set[str]:
    return {p.name for p in directory.iterdir()}


# ----------------------------- caso feliz ---------------------------------- #
def test_roundtrip(plain_file, key, sample_bytes, tmp_path):
    enc = encrypt_file(plain_file, key)
    assert enc == tmp_path / "documento.txt.enc"
    restored = decrypt_file(enc, key, tmp_path / "restaurado.txt")
    assert restored.read_bytes() == sample_bytes


def test_encrypt_does_not_touch_original(plain_file, key, sample_bytes):
    encrypt_file(plain_file, key)
    assert plain_file.read_bytes() == sample_bytes


def test_ciphertext_hides_plaintext(plain_file, key, sample_bytes):
    enc = encrypt_file(plain_file, key)
    assert b"confidencial" not in enc.read_bytes()


def test_same_input_produces_different_outputs(plain_file, key, tmp_path):
    a = encrypt_file(plain_file, key, tmp_path / "a.enc").read_bytes()
    b = encrypt_file(plain_file, key, tmp_path / "b.enc").read_bytes()
    assert a != b  # nonce aleatorio distinto en cada cifrado
    assert a[7:19] != b[7:19]


def test_default_decrypt_name_strips_extension(plain_file, key, sample_bytes):
    enc = encrypt_file(plain_file, key)
    plain_file.unlink()
    restored = decrypt_file(enc, key)
    assert restored == plain_file
    assert restored.read_bytes() == sample_bytes


@pytest.mark.parametrize(
    "size", [0, 1, 15, 16, 17, 1023, 4096, 65_537, 1024 * 1024, 5 * 1024 * 1024]
)
def test_various_sizes(tmp_path, key, size):
    original = secrets.token_bytes(size)
    src = tmp_path / "datos.bin"
    src.write_bytes(original)
    enc = encrypt_file(src, key)
    assert enc.stat().st_size == FIXED_HEADER_SIZE + 12 + size + 16
    out = decrypt_file(enc, key, tmp_path / "salida.bin")
    assert out.read_bytes() == original


def test_empty_file_roundtrip(tmp_path, key):
    src = tmp_path / "vacio.txt"
    src.write_bytes(b"")
    enc = encrypt_file(src, key)
    out = decrypt_file(enc, key, tmp_path / "vacio_restaurado.txt")
    assert out.read_bytes() == b""


def test_filename_with_spaces_and_unicode(tmp_path, key):
    src = tmp_path / "informe año 2026 ñ.txt"
    src.write_bytes(b"datos")
    enc = encrypt_file(src, key)
    assert decrypt_file(enc, key, tmp_path / "ok.txt").read_bytes() == b"datos"


# ----------------------------- entradas inválidas --------------------------- #
def test_nonexistent_input(tmp_path, key):
    with pytest.raises(FileOperationError, match="no existe"):
        encrypt_file(tmp_path / "fantasma.txt", key)
    with pytest.raises(FileOperationError, match="no existe"):
        decrypt_file(tmp_path / "fantasma.txt.enc", key)
    with pytest.raises(FileOperationError, match="no existe"):
        inspect_file(tmp_path / "fantasma.txt.enc")


def test_directory_as_input(tmp_path, key):
    with pytest.raises(FileOperationError, match="no es un archivo"):
        encrypt_file(tmp_path, key)


@pytest.mark.parametrize("bad_size", [0, 16, 31, 33])
def test_invalid_key_size_creates_nothing(plain_file, tmp_path, bad_size):
    before = _listing(tmp_path)
    with pytest.raises(InvalidKeyError):
        encrypt_file(plain_file, bytes(bad_size))
    assert _listing(tmp_path) == before


def test_unknown_algorithm(plain_file, key):
    with pytest.raises(UnsupportedAlgorithmError):
        encrypt_file(plain_file, key, algorithm="algoritmo-inventado")


def test_input_equals_output_rejected(plain_file, key):
    with pytest.raises(FileOperationError, match="mismo"):
        encrypt_file(plain_file, key, plain_file)


def test_missing_output_directory(plain_file, key, tmp_path):
    with pytest.raises(FileOperationError, match="directorio de salida"):
        encrypt_file(plain_file, key, tmp_path / "no_existe" / "x.enc")


def test_refuses_to_overwrite_existing_output(plain_file, key, tmp_path):
    existing = tmp_path / "documento.txt.enc"
    existing.write_bytes(b"importante")
    with pytest.raises(FileOperationError, match="ya existe"):
        encrypt_file(plain_file, key)
    assert existing.read_bytes() == b"importante"


def test_overwrite_when_explicit(plain_file, key, tmp_path):
    (tmp_path / "documento.txt.enc").write_bytes(b"viejo")
    out = encrypt_file(plain_file, key, overwrite=True)
    assert out.read_bytes() != b"viejo"


def test_decrypt_refuses_to_clobber_original(plain_file, key, sample_bytes):
    enc = encrypt_file(plain_file, key)
    with pytest.raises(FileOperationError, match="ya existe"):
        decrypt_file(enc, key)  # destino por defecto = documento.txt, que existe
    assert plain_file.read_bytes() == sample_bytes


def test_decrypt_without_enc_extension_requires_output(tmp_path, key, plain_file):
    enc = encrypt_file(plain_file, key, tmp_path / "datos.cifrado")
    with pytest.raises(FileOperationError, match="--output"):
        decrypt_file(enc, key)


def test_file_too_large(monkeypatch, plain_file, key):
    monkeypatch.setattr(service, "MAX_FILE_SIZE_BYTES", 10)
    with pytest.raises(FileOperationError, match="supera el máximo"):
        encrypt_file(plain_file, key)


# ----------------------- autenticación e integridad ------------------------ #
def test_wrong_key_fails_and_writes_nothing(plain_file, key, other_key, tmp_path):
    enc = encrypt_file(plain_file, key)
    plain_file.unlink()
    before = _listing(tmp_path)
    with pytest.raises(AuthenticationError, match="Autenticación fallida"):
        decrypt_file(enc, other_key)
    assert _listing(tmp_path) == before  # ni archivo parcial ni temporales
    assert not plain_file.exists()


@pytest.mark.parametrize(
    "offset",
    [NONCE_OFFSET, NONCE_OFFSET + 5, CIPHERTEXT_OFFSET, CIPHERTEXT_OFFSET + 100, -1, -16],
    ids=["nonce[0]", "nonce[5]", "ct[0]", "ct[100]", "tag[-1]", "tag[-16]"],
)
def test_tampered_byte_is_detected(plain_file, key, tmp_path, offset):
    enc = encrypt_file(plain_file, key)
    plain_file.unlink()
    data = bytearray(enc.read_bytes())
    data[offset] ^= 0x01
    enc.write_bytes(bytes(data))
    before = _listing(tmp_path)
    with pytest.raises(AuthenticationError):
        decrypt_file(enc, key)
    assert _listing(tmp_path) == before


def test_appended_data_is_detected(plain_file, key):
    enc = encrypt_file(plain_file, key)
    enc.write_bytes(enc.read_bytes() + b"basura")
    with pytest.raises(AuthenticationError):
        decrypt_file(enc, key, plain_file.with_name("x.txt"))


def test_truncated_ciphertext_is_detected(plain_file, key):
    enc = encrypt_file(plain_file, key)
    enc.write_bytes(enc.read_bytes()[:-1])
    with pytest.raises(AuthenticationError):
        decrypt_file(enc, key, plain_file.with_name("x.txt"))


def test_file_with_only_header_is_invalid(plain_file, key, tmp_path):
    enc = encrypt_file(plain_file, key)
    enc.write_bytes(enc.read_bytes()[:CIPHERTEXT_OFFSET])
    with pytest.raises(InvalidFileFormatError, match="truncado"):
        decrypt_file(enc, key, tmp_path / "x.txt")


def test_not_an_encrypted_file(tmp_path, key):
    fake = tmp_path / "falso.enc"
    fake.write_bytes(b"esto no es un archivo cifrado en absoluto")
    with pytest.raises(InvalidFileFormatError, match="firma"):
        decrypt_file(fake, key)


def test_empty_enc_file(tmp_path, key):
    fake = tmp_path / "vacio.enc"
    fake.write_bytes(b"")
    with pytest.raises(InvalidFileFormatError, match="demasiado corto"):
        decrypt_file(fake, key)


def test_tampered_version_is_rejected(plain_file, key, tmp_path):
    enc = encrypt_file(plain_file, key)
    data = bytearray(enc.read_bytes())
    data[4] = 9
    enc.write_bytes(bytes(data))
    with pytest.raises(UnsupportedVersionError):
        decrypt_file(enc, key, tmp_path / "x.txt")


def test_unknown_algorithm_id_in_file(plain_file, key, tmp_path):
    enc = encrypt_file(plain_file, key)
    data = bytearray(enc.read_bytes())
    data[5] = 99
    enc.write_bytes(bytes(data))
    with pytest.raises(UnsupportedAlgorithmError):
        decrypt_file(enc, key, tmp_path / "x.txt")


def test_inconsistent_nonce_length(plain_file, key, tmp_path):
    enc = encrypt_file(plain_file, key)
    data = bytearray(enc.read_bytes())
    data[6] = 8  # declara un nonce de 8 bytes aunque AES-GCM exige 12
    enc.write_bytes(bytes(data))
    with pytest.raises(InvalidFileFormatError, match="nonce"):
        decrypt_file(enc, key, tmp_path / "x.txt")


def test_no_temp_files_left_after_success(plain_file, key, tmp_path):
    encrypt_file(plain_file, key)
    assert not [n for n in _listing(tmp_path) if n.endswith(".tmp")]


# ------------------------------- inspect ----------------------------------- #
def test_inspect_reports_metadata(plain_file, key, sample_bytes):
    enc = encrypt_file(plain_file, key)
    info = inspect_file(enc)
    assert info.format_version == 1
    assert info.algorithm_id == 1
    assert info.algorithm_name == "aes-256-gcm"
    assert info.nonce_size == 12
    assert info.header_size == 19
    assert info.file_size == enc.stat().st_size
    assert info.plaintext_size == len(sample_bytes)


def test_inspect_never_exposes_key_or_nonce(plain_file, key):
    info = inspect_file(encrypt_file(plain_file, key))
    text = repr(info)
    assert key.hex() not in text
    assert not hasattr(info, "key") and not hasattr(info, "nonce")


def test_inspect_unknown_algorithm(plain_file, key):
    enc = encrypt_file(plain_file, key)
    data = bytearray(enc.read_bytes())
    data[5] = 77
    enc.write_bytes(bytes(data))
    info = inspect_file(enc)
    assert info.algorithm_name is None
    assert info.plaintext_size is None


def test_inspect_invalid_file(tmp_path):
    fake = tmp_path / "x.enc"
    fake.write_bytes(b"no soy un archivo cifrado")
    with pytest.raises(InvalidFileFormatError):
        inspect_file(fake)
