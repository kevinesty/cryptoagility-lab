"""Demostración de agilidad criptográfica.

Se registra un segundo algoritmo REAL (ChaCha20-Poly1305 de la biblioteca
``cryptography``) únicamente dentro de estas pruebas, sin tocar el código de la
aplicación. Demuestra que añadir un algoritmo solo exige implementar la interfaz
y registrarla. El registro se restaura tras cada prueba.
"""

from __future__ import annotations

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cryptoagility import encryption
from cryptoagility.cli import main
from cryptoagility.encryption import (
    CipherProvider,
    available_algorithms,
    get_cipher,
    register_cipher,
)
from cryptoagility.exceptions import (
    AuthenticationError,
    UnsupportedAlgorithmError,
)
from cryptoagility.key_manager import save_key
from cryptoagility.service import decrypt_file, encrypt_file, inspect_file


class ChaCha20Poly1305Provider(CipherProvider):
    name = "chacha20-poly1305"
    algorithm_id = 2
    key_size = 32
    nonce_size = 12
    tag_size = 16

    def encrypt(self, key, nonce, plaintext, associated_data):
        self.validate_key(key)
        self.validate_nonce(nonce)
        return ChaCha20Poly1305(bytes(key)).encrypt(nonce, plaintext, associated_data)

    def decrypt(self, key, nonce, ciphertext, associated_data):
        self.validate_key(key)
        self.validate_nonce(nonce)
        try:
            return ChaCha20Poly1305(bytes(key)).decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise AuthenticationError("Autenticación fallida.") from None


@pytest.fixture
def chacha(monkeypatch):
    """Registra ChaCha20-Poly1305 solo durante la prueba (aislando el registro global)."""
    monkeypatch.setattr(encryption, "_BY_NAME", dict(encryption._BY_NAME))
    monkeypatch.setattr(encryption, "_BY_ID", dict(encryption._BY_ID))
    register_cipher(ChaCha20Poly1305Provider())


def test_second_algorithm_is_listed(chacha):
    assert available_algorithms() == ["aes-256-gcm", "chacha20-poly1305"]


def test_registry_restored_after_test():
    assert available_algorithms() == ["aes-256-gcm"]
    with pytest.raises(UnsupportedAlgorithmError):
        get_cipher("chacha20-poly1305")


def test_encrypt_with_new_algorithm_and_autodetect_on_decrypt(chacha, plain_file, key, tmp_path, sample_bytes):
    enc = encrypt_file(plain_file, key, algorithm="chacha20-poly1305")
    assert inspect_file(enc).algorithm_name == "chacha20-poly1305"
    # decrypt_file NO recibe el algoritmo: lo lee de la cabecera.
    restored = decrypt_file(enc, key, tmp_path / "restaurado.txt")
    assert restored.read_bytes() == sample_bytes


def test_old_and_new_files_coexist(chacha, plain_file, key, tmp_path, sample_bytes):
    old = encrypt_file(plain_file, key, tmp_path / "viejo.enc", algorithm="aes-256-gcm")
    new = encrypt_file(plain_file, key, tmp_path / "nuevo.enc", algorithm="chacha20-poly1305")
    assert inspect_file(old).algorithm_id == 1
    assert inspect_file(new).algorithm_id == 2
    assert decrypt_file(old, key, tmp_path / "o.txt").read_bytes() == sample_bytes
    assert decrypt_file(new, key, tmp_path / "n.txt").read_bytes() == sample_bytes


def test_file_with_unregistered_algorithm_gives_clear_error(monkeypatch, plain_file, key, tmp_path):
    # Se crea con ChaCha20 registrado...
    with monkeypatch.context() as m:
        m.setattr(encryption, "_BY_NAME", dict(encryption._BY_NAME))
        m.setattr(encryption, "_BY_ID", dict(encryption._BY_ID))
        register_cipher(ChaCha20Poly1305Provider())
        enc = encrypt_file(plain_file, key, algorithm="chacha20-poly1305")
    # ...y se intenta abrir donde ya no está registrado.
    with pytest.raises(UnsupportedAlgorithmError, match="id 2"):
        decrypt_file(enc, key, tmp_path / "x.txt")


def test_tamper_detection_also_works_for_new_algorithm(chacha, plain_file, key, tmp_path):
    enc = encrypt_file(plain_file, key, algorithm="chacha20-poly1305")
    data = bytearray(enc.read_bytes())
    data[-1] ^= 1
    enc.write_bytes(bytes(data))
    with pytest.raises(AuthenticationError):
        decrypt_file(enc, key, tmp_path / "x.txt")


def test_algorithm_selectable_from_cli_and_config(chacha, plain_file, key, tmp_path, capsys, monkeypatch):
    key_path = save_key(key, tmp_path / "keys" / "k.key")
    assert main(["encrypt", str(plain_file), "-k", str(key_path), "-a", "chacha20-poly1305"]) == 0
    assert inspect_file(tmp_path / "documento.txt.enc").algorithm_name == "chacha20-poly1305"

    config = tmp_path / "cfg.json"
    config.write_text('{"algorithm": "chacha20-poly1305"}')
    out = tmp_path / "otro.enc"
    assert main(["encrypt", str(plain_file), "-k", str(key_path), "-c", str(config), "-o", str(out)]) == 0
    assert inspect_file(out).algorithm_name == "chacha20-poly1305"

    monkeypatch.setenv("CRYPTOAGILITY_ALGORITHM", "chacha20-poly1305")
    out2 = tmp_path / "env.enc"
    assert main(["encrypt", str(plain_file), "-k", str(key_path), "-o", str(out2)]) == 0
    assert inspect_file(out2).algorithm_name == "chacha20-poly1305"
