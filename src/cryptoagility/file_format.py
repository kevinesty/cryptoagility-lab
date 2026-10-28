"""Formato binario de los archivos cifrados (.enc).

Diseño (todos los enteros en big-endian)::

    Offset  Tamaño  Campo
    ------  ------  --------------------------------------------------------
    0       4       Firma mágica: b"CAGL"
    4       1       Versión del formato (actualmente 1)
    5       1       Identificador del algoritmo (1 = aes-256-gcm)
    6       1       Longitud del nonce en bytes (N)
    7       N       Nonce (público, aleatorio, único por cifrado)
    7+N     ...     Texto cifrado || etiqueta de autenticación

La cabecera completa (firma, versión, algoritmo, longitud y nonce) se usa como
*datos asociados autenticados* (AAD): no se cifra, pero cualquier modificación
hace fallar la verificación de la etiqueta.

La clave **nunca** forma parte del archivo.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from .exceptions import InvalidFileFormatError, UnsupportedVersionError

MAGIC: Final[bytes] = b"CAGL"
FORMAT_VERSION: Final[int] = 1
FILE_EXTENSION: Final[str] = ".enc"

_FIXED = struct.Struct(">4sBBB")
FIXED_HEADER_SIZE: Final[int] = _FIXED.size  # 7 bytes
MAX_HEADER_SIZE: Final[int] = FIXED_HEADER_SIZE + 255


@dataclass(frozen=True)
class EncryptedFileHeader:
    """Cabecera no sensible de un archivo cifrado."""

    algorithm_id: int
    nonce: bytes
    version: int = FORMAT_VERSION

    def __post_init__(self) -> None:
        if not 0 <= self.version <= 255:
            raise ValueError("La versión debe estar entre 0 y 255.")
        if not 0 <= self.algorithm_id <= 255:
            raise ValueError("El identificador de algoritmo debe estar entre 0 y 255.")
        if not 1 <= len(self.nonce) <= 255:
            raise ValueError("El nonce debe tener entre 1 y 255 bytes.")

    @property
    def size(self) -> int:
        """Tamaño en bytes de la cabecera serializada."""
        return FIXED_HEADER_SIZE + len(self.nonce)

    def to_bytes(self) -> bytes:
        """Serializa la cabecera (también se usa como AAD)."""
        return _FIXED.pack(MAGIC, self.version, self.algorithm_id, len(self.nonce)) + self.nonce


def parse_header(data: bytes) -> EncryptedFileHeader:
    """Interpreta la cabecera al inicio de ``data`` validándola estrictamente."""
    if len(data) < FIXED_HEADER_SIZE:
        raise InvalidFileFormatError(
            "El archivo es demasiado corto para ser un archivo cifrado válido."
        )
    magic, version, algorithm_id, nonce_len = _FIXED.unpack_from(data)
    if magic != MAGIC:
        raise InvalidFileFormatError(
            "El archivo no parece haber sido cifrado con CryptoAgility Lab (firma incorrecta)."
        )
    if version != FORMAT_VERSION:
        raise UnsupportedVersionError(
            f"Versión de formato no soportada: {version} (esta instalación soporta "
            f"la versión {FORMAT_VERSION})."
        )
    if nonce_len == 0:
        raise InvalidFileFormatError("Cabecera inválida: longitud de nonce igual a cero.")
    end = FIXED_HEADER_SIZE + nonce_len
    if len(data) < end:
        raise InvalidFileFormatError("Cabecera truncada: el archivo está incompleto.")
    return EncryptedFileHeader(
        algorithm_id=algorithm_id,
        nonce=bytes(data[FIXED_HEADER_SIZE:end]),
        version=version,
    )


def build_encrypted_file(header: EncryptedFileHeader, ciphertext: bytes) -> bytes:
    """Concatena cabecera y ``ciphertext || tag`` en el contenido final del archivo."""
    return header.to_bytes() + ciphertext


def split_encrypted_file(data: bytes) -> tuple[EncryptedFileHeader, bytes]:
    """Separa un archivo cifrado en su cabecera y el bloque ``ciphertext || tag``."""
    header = parse_header(data)
    return header, bytes(data[header.size :])
