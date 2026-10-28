"""Servicio de archivos: orquesta lectura, cifrado/descifrado y escritura.

Garantías relevantes:

* El descifrado se realiza **en memoria**: si la autenticación falla no se crea
  ningún archivo de salida (ni parcial ni temporal).
* La escritura es atómica: primero a un archivo temporal en el mismo directorio y
  después ``os.replace``. Un fallo a mitad no deja archivos corruptos.
* No se sobrescribe ningún archivo existente salvo ``overwrite=True``.
* El archivo original nunca se modifica ni se borra.

Limitación: el archivo completo se carga en memoria (tope ``MAX_FILE_SIZE_BYTES``).
Un diseño por bloques/streaming queda como mejora futura.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .encryption import DEFAULT_ALGORITHM, get_cipher, get_cipher_by_id
from .exceptions import FileOperationError, InvalidFileFormatError, UnsupportedAlgorithmError
from .file_format import (
    FILE_EXTENSION,
    MAX_HEADER_SIZE,
    EncryptedFileHeader,
    build_encrypted_file,
    parse_header,
    split_encrypted_file,
)

MAX_FILE_SIZE_BYTES = 256 * 1024 * 1024  # 256 MiB


@dataclass(frozen=True)
class FileInfo:
    """Metadatos no sensibles de un archivo cifrado."""

    path: Path
    format_version: int
    algorithm_id: int
    algorithm_name: str | None  # None si el algoritmo no está registrado aquí
    nonce_size: int
    header_size: int
    file_size: int
    payload_size: int  # ciphertext + etiqueta
    plaintext_size: int | None  # estimado; None si no se puede calcular


def _check_input_file(path: Path) -> None:
    if not path.exists():
        raise FileOperationError(f"El archivo no existe: {path}")
    if not path.is_file():
        raise FileOperationError(f"La ruta no es un archivo regular: {path}")


def _read_input(path: Path) -> bytes:
    _check_input_file(path)
    try:
        size = path.stat().st_size
        if size > MAX_FILE_SIZE_BYTES:
            raise FileOperationError(
                f"El archivo ocupa {size} bytes y supera el máximo soportado "
                f"({MAX_FILE_SIZE_BYTES} bytes) porque se procesa completo en memoria."
            )
        return path.read_bytes()
    except OSError as exc:
        raise FileOperationError(f"No se pudo leer {path}: {exc.strerror or exc}") from exc


def _write_atomic(path: Path, data: bytes, *, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise FileOperationError(
            f"El archivo de salida ya existe: {path}. Usa --force para sobrescribirlo."
        )
    if path.exists() and not path.is_file():
        raise FileOperationError(f"La ruta de salida no es un archivo regular: {path}")
    if not path.parent.is_dir():
        raise FileOperationError(f"El directorio de salida no existe: {path.parent}")
    tmp_name: str | None = None
    try:
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".cagl-", suffix=".tmp")
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
        tmp_name = None
    except OSError as exc:
        raise FileOperationError(f"No se pudo escribir {path}: {exc.strerror or exc}") from exc
    finally:
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass


def _ensure_distinct(input_path: Path, output_path: Path) -> None:
    if input_path.resolve() == output_path.resolve():
        raise FileOperationError("El archivo de salida no puede ser el mismo que el de entrada.")


def encrypt_file(
    input_path: Path | str,
    key: bytes,
    output_path: Path | str | None = None,
    algorithm: str = DEFAULT_ALGORITHM,
    *,
    overwrite: bool = False,
) -> Path:
    """Cifra ``input_path`` y devuelve la ruta del archivo ``.enc`` creado."""
    source = Path(input_path)
    provider = get_cipher(algorithm)
    provider.validate_key(key)

    target = Path(output_path) if output_path else source.with_name(source.name + FILE_EXTENSION)
    _check_input_file(source)
    _ensure_distinct(source, target)

    plaintext = _read_input(source)
    header = EncryptedFileHeader(
        algorithm_id=provider.algorithm_id, nonce=provider.generate_nonce()
    )
    # La cabecera viaja en claro pero queda autenticada como AAD.
    ciphertext = provider.encrypt(key, header.nonce, plaintext, header.to_bytes())
    _write_atomic(target, build_encrypted_file(header, ciphertext), overwrite=overwrite)
    return target


def decrypt_file(
    input_path: Path | str,
    key: bytes,
    output_path: Path | str | None = None,
    *,
    overwrite: bool = False,
) -> Path:
    """Verifica y descifra ``input_path``; devuelve la ruta del archivo restaurado.

    El algoritmo se determina a partir de la cabecera del archivo.
    """
    source = Path(input_path)
    _check_input_file(source)

    if output_path:
        target = Path(output_path)
    elif source.suffix.lower() == FILE_EXTENSION and len(source.name) > len(FILE_EXTENSION):
        target = source.with_suffix("")
    else:
        raise FileOperationError(
            f"El archivo no termina en '{FILE_EXTENSION}'; indica el destino con --output."
        )
    _ensure_distinct(source, target)

    data = _read_input(source)
    header, payload = split_encrypted_file(data)
    provider = get_cipher_by_id(header.algorithm_id)
    if len(header.nonce) != provider.nonce_size:
        raise InvalidFileFormatError(
            "Cabecera inconsistente: el tamaño del nonce no coincide con el algoritmo."
        )
    if len(payload) < provider.tag_size:
        raise InvalidFileFormatError(
            "El archivo está truncado: falta la etiqueta de autenticación."
        )
    provider.validate_key(key)

    plaintext = provider.decrypt(key, header.nonce, payload, header.to_bytes())
    # Solo se llega aquí si la autenticación fue correcta.
    _write_atomic(target, plaintext, overwrite=overwrite)
    return target


def inspect_file(input_path: Path | str) -> FileInfo:
    """Lee únicamente la cabecera y devuelve metadatos no sensibles (no requiere clave)."""
    source = Path(input_path)
    _check_input_file(source)
    try:
        file_size = source.stat().st_size
        with source.open("rb") as handle:
            head = handle.read(MAX_HEADER_SIZE)
    except OSError as exc:
        raise FileOperationError(f"No se pudo leer {source}: {exc.strerror or exc}") from exc

    header = parse_header(head)
    payload_size = file_size - header.size

    name: str | None = None
    plaintext_size: int | None = None
    try:
        provider = get_cipher_by_id(header.algorithm_id)
    except UnsupportedAlgorithmError:  # algoritmo desconocido: se informa sin fallar
        provider = None
    if provider is not None:
        name = provider.name
        if payload_size >= provider.tag_size:
            plaintext_size = payload_size - provider.tag_size

    return FileInfo(
        path=source,
        format_version=header.version,
        algorithm_id=header.algorithm_id,
        algorithm_name=name,
        nonce_size=len(header.nonce),
        header_size=header.size,
        file_size=file_size,
        payload_size=payload_size,
        plaintext_size=plaintext_size,
    )
