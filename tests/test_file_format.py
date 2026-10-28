"""Pruebas del formato binario .enc."""

from __future__ import annotations

import pytest

from cryptoagility.exceptions import InvalidFileFormatError, UnsupportedVersionError
from cryptoagility.file_format import (
    FIXED_HEADER_SIZE,
    FORMAT_VERSION,
    MAGIC,
    EncryptedFileHeader,
    build_encrypted_file,
    parse_header,
    split_encrypted_file,
)

NONCE = bytes(range(12))


def test_header_roundtrip():
    header = EncryptedFileHeader(algorithm_id=1, nonce=NONCE)
    parsed = parse_header(header.to_bytes())
    assert parsed == header
    assert header.size == FIXED_HEADER_SIZE + 12


def test_header_layout_is_stable():
    raw = EncryptedFileHeader(algorithm_id=1, nonce=NONCE).to_bytes()
    assert raw[:4] == MAGIC == b"CAGL"
    assert raw[4] == FORMAT_VERSION == 1
    assert raw[5] == 1
    assert raw[6] == 12
    assert raw[7:] == NONCE


def test_split_returns_payload():
    header = EncryptedFileHeader(algorithm_id=1, nonce=NONCE)
    data = build_encrypted_file(header, b"PAYLOAD")
    parsed, payload = split_encrypted_file(data)
    assert parsed == header
    assert payload == b"PAYLOAD"


def test_bad_magic():
    raw = bytearray(EncryptedFileHeader(algorithm_id=1, nonce=NONCE).to_bytes())
    raw[0] = ord("X")
    with pytest.raises(InvalidFileFormatError, match="firma"):
        parse_header(bytes(raw))


@pytest.mark.parametrize("data", [b"", b"CAG", b"CAGL\x01\x01"])
def test_too_short(data):
    with pytest.raises(InvalidFileFormatError):
        parse_header(data)


def test_unsupported_version():
    raw = bytearray(EncryptedFileHeader(algorithm_id=1, nonce=NONCE).to_bytes())
    raw[4] = 99
    with pytest.raises(UnsupportedVersionError):
        parse_header(bytes(raw))


def test_truncated_nonce():
    raw = EncryptedFileHeader(algorithm_id=1, nonce=NONCE).to_bytes()[:-3]
    with pytest.raises(InvalidFileFormatError, match="truncada"):
        parse_header(raw)


def test_zero_nonce_length():
    raw = MAGIC + bytes([FORMAT_VERSION, 1, 0])
    with pytest.raises(InvalidFileFormatError):
        parse_header(raw)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"algorithm_id": 256, "nonce": NONCE},
        {"algorithm_id": -1, "nonce": NONCE},
        {"algorithm_id": 1, "nonce": b""},
        {"algorithm_id": 1, "nonce": bytes(256)},
        {"algorithm_id": 1, "nonce": NONCE, "version": 300},
    ],
)
def test_header_validation(kwargs):
    with pytest.raises(ValueError):
        EncryptedFileHeader(**kwargs)
