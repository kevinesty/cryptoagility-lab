"""Gestión básica de claves.

Principios aplicados:

* Las claves se generan con el CSPRNG del sistema operativo (``secrets``).
* La clave vive en un archivo **separado** del archivo cifrado (por defecto ``keys/``).
* Nunca se imprime ni se registra: las funciones de este módulo no escriben claves
  en consola y los mensajes de error jamás incluyen su contenido.
* El archivo de clave se crea con permisos 0600 en sistemas POSIX y no se
  sobrescribe salvo petición explícita.

Limitaciones (ver README): en Windows ``os.open(..., 0o600)`` apenas afecta a las
ACL; Python no puede borrar de forma segura la memoria; esto no sustituye a un
gestor de secretos (KMS/HSM) ni a un derivador de claves a partir de contraseña.
"""

from __future__ import annotations

import base64
import binascii
import os
import secrets
import stat
from pathlib import Path

from .exceptions import KeyFileError

DEFAULT_KEY_PATH = Path("keys") / "default.key"
_MAX_KEY_FILE_BYTES = 4096


def generate_key(key_size: int = 32) -> bytes:
    """Genera ``key_size`` bytes aleatorios criptográficamente seguros."""
    if key_size < 16:
        raise ValueError("El tamaño mínimo de clave permitido es 16 bytes.")
    return secrets.token_bytes(key_size)


def encode_key(key: bytes) -> str:
    """Codifica una clave en Base64 URL-safe para guardarla como texto."""
    return base64.urlsafe_b64encode(key).decode("ascii")


def save_key(key: bytes, path: Path | str, *, overwrite: bool = False) -> Path:
    """Guarda la clave en ``path`` (Base64) con permisos restrictivos.

    Por defecto falla si el archivo ya existe, para no destruir claves por accidente.
    """
    target = Path(path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_BINARY", 0)
        flags |= os.O_TRUNC if overwrite else os.O_EXCL
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        raise KeyFileError(
            f"El archivo de clave ya existe: {target}. Usa --force solo si estás seguro "
            "de querer reemplazarlo (los archivos cifrados con la clave anterior "
            "quedarían irrecuperables)."
        ) from None
    except OSError as exc:
        raise KeyFileError(
            f"No se pudo crear el archivo de clave {target}: {exc.strerror or exc}"
        ) from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(encode_key(key).encode("ascii") + b"\n")
    except OSError as exc:
        raise KeyFileError(
            f"No se pudo escribir el archivo de clave {target}: {exc.strerror or exc}"
        ) from exc
    return target


def load_key(path: Path | str, *, expected_size: int | None = None) -> bytes:
    """Carga y valida una clave guardada con :func:`save_key`."""
    source = Path(path)
    if not source.exists():
        raise KeyFileError(
            f"No se encontró el archivo de clave: {source}. "
            "Genera uno con el comando 'generate-key'."
        )
    if not source.is_file():
        raise KeyFileError(f"La ruta de la clave no es un archivo: {source}")
    try:
        if source.stat().st_size > _MAX_KEY_FILE_BYTES:
            raise KeyFileError(f"El archivo de clave es sospechosamente grande: {source}")
        raw = source.read_bytes().strip()
    except OSError as exc:
        raise KeyFileError(
            f"No se pudo leer el archivo de clave {source}: {exc.strerror or exc}"
        ) from exc
    if not raw:
        raise KeyFileError(f"El archivo de clave está vacío: {source}")
    try:
        key = base64.b64decode(raw, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        # Importante: no se incluye el contenido del archivo en el mensaje.
        raise KeyFileError(
            f"El archivo de clave no tiene un formato Base64 válido: {source}"
        ) from None
    if expected_size is not None and len(key) != expected_size:
        raise KeyFileError(
            f"La clave en {source} tiene {len(key)} bytes; se esperaban {expected_size}."
        )
    return key


def key_file_permissions_too_open(path: Path | str) -> bool:
    """Devuelve ``True`` si en POSIX el archivo es accesible por grupo u otros.

    En Windows devuelve siempre ``False`` (el modelo de permisos es distinto).
    """
    if os.name != "posix":
        return False
    try:
        mode = Path(path).stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IRWXG | stat.S_IRWXO))
