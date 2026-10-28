"""Capa de cifrado: interfaz abstracta, implementaciones y registro de algoritmos.

Esta es la pieza central de la *agilidad criptográfica*. El resto de la aplicación
(servicio de archivos, CLI) solo conoce la interfaz :class:`CipherProvider` y el
registro de algoritmos; nunca importa AES directamente. Para añadir un algoritmo
nuevo basta con implementar la interfaz y registrarlo (ver ``docs/anadir-un-algoritmo.md``).

No se implementa ninguna primitiva criptográfica propia: todo se delega en la
biblioteca ``cryptography``.
"""

from __future__ import annotations

import secrets
from abc import ABC, abstractmethod
from typing import ClassVar

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import (
    AuthenticationError,
    InvalidKeyError,
    UnsupportedAlgorithmError,
)

DEFAULT_ALGORITHM = "aes-256-gcm"


class CipherProvider(ABC):
    """Contrato que debe cumplir cualquier algoritmo de cifrado autenticado (AEAD).

    Atributos de clase que cada implementación debe definir:

    * ``name``: identificador legible y estable (p. ej. ``"aes-256-gcm"``).
    * ``algorithm_id``: entero 1-255 que se guarda en la cabecera del archivo.
      **Nunca** debe reutilizarse para otro algoritmo.
    * ``key_size``: tamaño de la clave en bytes.
    * ``nonce_size``: tamaño del nonce en bytes.
    * ``tag_size``: tamaño de la etiqueta de autenticación en bytes.
    """

    name: ClassVar[str]
    algorithm_id: ClassVar[int]
    key_size: ClassVar[int]
    nonce_size: ClassVar[int]
    tag_size: ClassVar[int]

    def generate_key(self) -> bytes:
        """Genera una clave aleatoria con el generador criptográfico del sistema operativo."""
        return secrets.token_bytes(self.key_size)

    def generate_nonce(self) -> bytes:
        """Genera un nonce aleatorio del tamaño que exige el algoritmo."""
        return secrets.token_bytes(self.nonce_size)

    def validate_key(self, key: bytes) -> None:
        """Comprueba tipo y longitud de la clave sin revelar su contenido."""
        if not isinstance(key, (bytes, bytearray)):
            raise InvalidKeyError("La clave debe ser un valor de tipo bytes.")
        if len(key) != self.key_size:
            raise InvalidKeyError(
                f"La clave para '{self.name}' debe tener {self.key_size} bytes "
                f"({self.key_size * 8} bits); se recibieron {len(key)} bytes."
            )

    def validate_nonce(self, nonce: bytes) -> None:
        """Comprueba la longitud del nonce."""
        if len(nonce) != self.nonce_size:
            raise ValueError(
                f"El nonce para '{self.name}' debe tener {self.nonce_size} bytes; "
                f"se recibieron {len(nonce)}."
            )

    @abstractmethod
    def encrypt(
        self, key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
    ) -> bytes:
        """Cifra y autentica. Devuelve ``ciphertext || tag``."""

    @abstractmethod
    def decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes
    ) -> bytes:
        """Verifica y descifra. Lanza :class:`AuthenticationError` si la verificación falla."""


class AesGcm256Provider(CipherProvider):
    """AES-256 en modo GCM (AEAD) mediante ``cryptography.hazmat...AESGCM``.

    * Clave de 256 bits, nonce de 96 bits (tamaño recomendado por NIST SP 800-38D),
      etiqueta de autenticación de 128 bits.
    * Con nonces aleatorios, NIST recomienda no superar 2**32 cifrados con la misma clave.
    """

    name = "aes-256-gcm"
    algorithm_id = 1
    key_size = 32
    nonce_size = 12
    tag_size = 16

    def encrypt(
        self, key: bytes, nonce: bytes, plaintext: bytes, associated_data: bytes
    ) -> bytes:
        self.validate_key(key)
        self.validate_nonce(nonce)
        return AESGCM(bytes(key)).encrypt(nonce, plaintext, associated_data)

    def decrypt(
        self, key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes
    ) -> bytes:
        self.validate_key(key)
        self.validate_nonce(nonce)
        try:
            return AESGCM(bytes(key)).decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            # No se distingue "clave incorrecta" de "datos alterados": un atacante no
            # debe obtener información adicional y, criptográficamente, son indistinguibles.
            raise AuthenticationError(
                "Autenticación fallida: la clave es incorrecta o el archivo cifrado "
                "fue modificado o está corrupto. No se ha escrito ningún archivo de salida."
            ) from None


# --------------------------------------------------------------------------- #
# Registro de algoritmos
# --------------------------------------------------------------------------- #
_BY_NAME: dict[str, CipherProvider] = {}
_BY_ID: dict[int, CipherProvider] = {}


def register_cipher(provider: CipherProvider) -> None:
    """Registra un algoritmo. Falla si el nombre o el identificador ya están en uso."""
    if not 1 <= provider.algorithm_id <= 255:
        raise ValueError("algorithm_id debe estar entre 1 y 255.")
    if provider.name in _BY_NAME:
        raise ValueError(f"Ya existe un algoritmo registrado con el nombre '{provider.name}'.")
    if provider.algorithm_id in _BY_ID:
        raise ValueError(f"Ya existe un algoritmo registrado con el id {provider.algorithm_id}.")
    _BY_NAME[provider.name] = provider
    _BY_ID[provider.algorithm_id] = provider


def get_cipher(name: str) -> CipherProvider:
    """Obtiene un algoritmo por nombre (sin distinguir mayúsculas)."""
    try:
        return _BY_NAME[name.strip().lower()]
    except KeyError:
        raise UnsupportedAlgorithmError(
            f"Algoritmo no soportado: '{name}'. Disponibles: {', '.join(available_algorithms())}."
        ) from None


def get_cipher_by_id(algorithm_id: int) -> CipherProvider:
    """Obtiene un algoritmo por el identificador guardado en la cabecera del archivo."""
    try:
        return _BY_ID[algorithm_id]
    except KeyError:
        raise UnsupportedAlgorithmError(
            f"El archivo usa el algoritmo con id {algorithm_id}, que no está registrado "
            "en esta instalación."
        ) from None


def available_algorithms() -> list[str]:
    """Nombres de los algoritmos registrados, ordenados por identificador."""
    return [p.name for p in sorted(_BY_ID.values(), key=lambda p: p.algorithm_id)]


register_cipher(AesGcm256Provider())
