"""Selección del algoritmo mediante configuración.

Orden de precedencia (de mayor a menor):

1. Opción de línea de comandos ``--algorithm``.
2. Variable de entorno ``CRYPTOAGILITY_ALGORITHM``.
3. Archivo JSON indicado con ``--config`` (clave ``"algorithm"``).
4. Valor por defecto: ``aes-256-gcm``.

Solo se configura el algoritmo para **cifrar**. Al descifrar, el algoritmo se lee
de la cabecera del archivo: así los archivos antiguos siguen siendo legibles aunque
la configuración cambie (esa es la esencia de la agilidad criptográfica).
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from .encryption import DEFAULT_ALGORITHM, get_cipher
from .exceptions import ConfigError

ENV_VAR = "CRYPTOAGILITY_ALGORITHM"
_ALLOWED_KEYS = {"algorithm"}


@dataclass(frozen=True)
class Config:
    """Configuración efectiva de la aplicación."""

    algorithm: str = DEFAULT_ALGORITHM


def _read_config_file(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise ConfigError(f"No se encontró el archivo de configuración: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"No se pudo leer la configuración {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"La configuración {path} debe ser un objeto JSON.")
    unknown = set(data) - _ALLOWED_KEYS
    if unknown:
        raise ConfigError(
            f"Claves desconocidas en {path}: {', '.join(sorted(unknown))}. "
            f"Permitidas: {', '.join(sorted(_ALLOWED_KEYS))}."
        )
    return data


def load_config(
    config_path: Path | str | None = None,
    cli_algorithm: str | None = None,
    env: Mapping[str, str] | None = None,
) -> Config:
    """Resuelve la configuración efectiva y valida que el algoritmo esté registrado."""
    environment = os.environ if env is None else env
    algorithm: object = DEFAULT_ALGORITHM

    if config_path is not None:
        algorithm = _read_config_file(Path(config_path)).get("algorithm", algorithm)
    if environment.get(ENV_VAR):
        algorithm = environment[ENV_VAR]
    if cli_algorithm:
        algorithm = cli_algorithm

    if not isinstance(algorithm, str):
        raise ConfigError("El valor de 'algorithm' debe ser una cadena de texto.")
    return Config(algorithm=get_cipher(algorithm).name)
