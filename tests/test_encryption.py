"""Pruebas de la capa de cifrado y del registro de algoritmos."""

from __future__ import annotations

import pytest

from cryptoagility import encryption
from cryptoagility.encryption import (
    AesGcm256Provider,
    available_algorithms,
    get_cipher,
    get_cipher_by_id,
    register_cipher,
)
from cryptoagility.exceptions import (
    AuthenticationError,
    InvalidKeyError,
    UnsupportedAlgorithmError,
)

NONCE = bytes(12)


@pytest.fixture
def provider() -> AesGcm256Provider:
    return AesGcm256Provider()


def test_known_answer_nist_gcm_test_case_13_and_14(provider):
    """Vectores de prueba oficiales de GCM (McGrew & Viega, AES-256, clave e IV a cero)."""
    zero_key = bytes(32)
    # Caso 13: texto vacío -> solo etiqueta.
    out = provider.encrypt(zero_key, NONCE, b"", b"")
    assert out.hex() == "530f8afbc74536b9a963b4f1c4cb738b"
    # Caso 14: 16 bytes a cero.
    out = provider.encrypt(zero_key, NONCE, bytes(16), b"")
    assert out.hex() == "cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919"


def test_roundtrip(provider, key):
    ct = provider.encrypt(key, NONCE, b"hola", b"aad")
    assert provider.decrypt(key, NONCE, ct, b"aad") == b"hola"


def test_ciphertext_has_tag_appended(provider, key):
    assert len(provider.encrypt(key, NONCE, b"x" * 100, b"")) == 100 + provider.tag_size


def test_wrong_key_fails(provider, key, other_key):
    ct = provider.encrypt(key, NONCE, b"secreto", b"")
    with pytest.raises(AuthenticationError):
        provider.decrypt(other_key, NONCE, ct, b"")


def test_wrong_associated_data_fails(provider, key):
    ct = provider.encrypt(key, NONCE, b"secreto", b"cabecera-v1")
    with pytest.raises(AuthenticationError):
        provider.decrypt(key, NONCE, ct, b"cabecera-v2")


def test_tampered_ciphertext_fails(provider, key):
    ct = bytearray(provider.encrypt(key, NONCE, b"secreto", b""))
    ct[0] ^= 0x01
    with pytest.raises(AuthenticationError):
        provider.decrypt(key, NONCE, bytes(ct), b"")


@pytest.mark.parametrize("size", [0, 16, 24, 31, 33, 64])
def test_invalid_key_sizes_rejected(provider, size):
    with pytest.raises(InvalidKeyError):
        provider.encrypt(bytes(size), NONCE, b"x", b"")


def test_invalid_key_type_rejected(provider):
    with pytest.raises(InvalidKeyError):
        provider.validate_key("no-son-bytes")  # type: ignore[arg-type]


def test_invalid_key_error_does_not_leak_key(provider):
    bad = b"SECRETO-DE-PRUEBA"
    with pytest.raises(InvalidKeyError) as exc:
        provider.validate_key(bad)
    assert "SECRETO" not in str(exc.value)


def test_invalid_nonce_size_rejected(provider, key):
    with pytest.raises(ValueError):
        provider.encrypt(key, b"corto", b"x", b"")


def test_nonces_are_random_and_correct_size(provider):
    nonces = {provider.generate_nonce() for _ in range(1000)}
    assert len(nonces) == 1000
    assert all(len(n) == 12 for n in nonces)


def test_generated_keys_are_unique_and_256_bits(provider):
    keys = {provider.generate_key() for _ in range(100)}
    assert len(keys) == 100
    assert all(len(k) == 32 for k in keys)


def test_registry_lookup(provider):
    assert get_cipher("AES-256-GCM").name == "aes-256-gcm"
    assert get_cipher("  aes-256-gcm ").algorithm_id == 1
    assert get_cipher_by_id(1).name == "aes-256-gcm"
    assert "aes-256-gcm" in available_algorithms()


def test_unknown_algorithm_by_name():
    with pytest.raises(UnsupportedAlgorithmError, match="rot13"):
        get_cipher("rot13")


def test_unknown_algorithm_by_id():
    with pytest.raises(UnsupportedAlgorithmError):
        get_cipher_by_id(200)


def test_duplicate_registration_rejected():
    with pytest.raises(ValueError):
        register_cipher(AesGcm256Provider())


def test_registry_is_consistent():
    assert set(encryption._BY_NAME) == {p.name for p in encryption._BY_ID.values()}
