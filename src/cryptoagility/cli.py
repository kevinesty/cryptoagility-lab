"""Interfaz de línea de comandos (argparse).

Códigos de salida:

* ``0``  éxito
* ``1``  error de uso, E/S, formato o configuración
* ``2``  argumentos inválidos (lo emite argparse)
* ``3``  fallo de autenticación (clave incorrecta o archivo modificado)
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import ENV_VAR, load_config
from .encryption import available_algorithms, get_cipher
from .exceptions import AuthenticationError, CryptoAgilityError
from .key_manager import (
    DEFAULT_KEY_PATH,
    key_file_permissions_too_open,
    load_key,
    save_key,
)
from .service import decrypt_file, encrypt_file, inspect_file

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_AUTH_FAILURE = 3


def _configure_output_streams() -> None:
    """Evita que la codificación de la consola/tubería rompa la ejecución.

    La codificación de ``stdout``/``stderr`` depende del sistema (en Windows, con
    tuberías o redirecciones, suele ser cp1252; en otras configuraciones puede ser
    ASCII). Si un mensaje contiene un carácter no representable, Python lanzaría
    ``UnicodeEncodeError`` a mitad de un comando, incluso después de haber realizado
    la operación (p. ej. tras guardar una clave). Se conserva la codificación del
    sistema, pero los caracteres no representables se sustituyen por ``?``.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):  # flujo cerrado o no reconfigurable
                pass


def _warn(message: str) -> None:
    print(f"Advertencia: {message}", file=sys.stderr)


def _error(message: str) -> None:
    print(f"Error: {message}", file=sys.stderr)


def _warn_about_key_location(data_file: Path, key_file: Path) -> None:
    """Avisa si la clave está en la misma carpeta que el archivo a proteger."""
    try:
        same_dir = data_file.resolve().parent == key_file.resolve().parent
    except OSError:
        same_dir = False
    if same_dir:
        _warn(
            "la clave está en la misma carpeta que el archivo. Guardar la clave junto al "
            "archivo cifrado anula la protección; muévela a otro lugar."
        )
    if key_file_permissions_too_open(key_file):
        _warn(
            f"el archivo de clave {key_file} es accesible por otros usuarios. "
            "Restringe los permisos (por ejemplo: chmod 600)."
        )


# --------------------------------------------------------------------------- #
# Manejadores de comandos
# --------------------------------------------------------------------------- #
def _cmd_generate_key(args: argparse.Namespace) -> int:
    config = load_config(args.config, args.algorithm)
    provider = get_cipher(config.algorithm)
    key = provider.generate_key()
    path = save_key(key, args.output, overwrite=args.force)
    print(f"[OK] Clave de {provider.key_size * 8} bits para '{provider.name}' guardada en: {path}")
    print("     La clave NO se muestra en pantalla.")
    print("     Guárdala separada de los archivos cifrados y haz una copia de seguridad segura:")
    print("     sin ella, los datos cifrados son irrecuperables.")
    return EXIT_OK


def _cmd_encrypt(args: argparse.Namespace) -> int:
    config = load_config(args.config, args.algorithm)
    key = load_key(args.key_file)
    _warn_about_key_location(args.file, args.key_file)
    output = encrypt_file(
        args.file, key, args.output, config.algorithm, overwrite=args.force
    )
    print(f"[OK] Archivo cifrado con {config.algorithm}: {output}")
    print("     El archivo original no se ha modificado ni eliminado.")
    return EXIT_OK


def _cmd_decrypt(args: argparse.Namespace) -> int:
    key = load_key(args.key_file)
    _warn_about_key_location(args.file, args.key_file)
    output = decrypt_file(args.file, key, args.output, overwrite=args.force)
    print(f"[OK] Autenticidad e integridad verificadas. Archivo descifrado: {output}")
    return EXIT_OK


def _cmd_inspect(args: argparse.Namespace) -> int:
    info = inspect_file(args.file)
    algorithm = (
        f"{info.algorithm_name} (id={info.algorithm_id})"
        if info.algorithm_name
        else f"desconocido en esta instalación (id={info.algorithm_id})"
    )
    plaintext = (
        f"{info.plaintext_size} bytes" if info.plaintext_size is not None else "no disponible"
    )
    print(f"Archivo:                     {info.path}")
    print(f"Formato:                     CAGL, versión {info.format_version}")
    print(f"Algoritmo:                   {algorithm}")
    print(f"Tamaño del nonce:            {info.nonce_size} bytes")
    print(f"Tamaño de la cabecera:       {info.header_size} bytes")
    print(f"Tamaño total del archivo:    {info.file_size} bytes")
    print(f"Texto cifrado + etiqueta:    {info.payload_size} bytes")
    print(f"Tamaño original (estimado):  {plaintext}")
    print("Nota: 'inspect' no usa ninguna clave y por tanto NO verifica la integridad.")
    return EXIT_OK


def _cmd_algorithms(_: argparse.Namespace) -> int:
    print("Algoritmos disponibles:")
    for name in available_algorithms():
        provider = get_cipher(name)
        print(
            f"  - {provider.name} (id={provider.algorithm_id}, clave={provider.key_size * 8} bits, "
            f"nonce={provider.nonce_size * 8} bits, etiqueta={provider.tag_size * 8} bits)"
        )
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Construcción del parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos con todos los subcomandos."""
    parser = argparse.ArgumentParser(
        prog="cryptoagility",
        description="CryptoAgility Lab: cifrado de archivos con AES-256-GCM y agilidad "
        "criptográfica. Proyecto educativo; no apto para producción.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="comando")

    algo = argparse.ArgumentParser(add_help=False)
    algo.add_argument(
        "--algorithm",
        "-a",
        help=f"Algoritmo a usar (también vía {ENV_VAR} o --config). Ver comando 'algorithms'.",
    )
    algo.add_argument("--config", "-c", type=Path, help="Archivo JSON de configuración.")

    key_opt = argparse.ArgumentParser(add_help=False)
    key_opt.add_argument(
        "--key-file",
        "-k",
        type=Path,
        default=DEFAULT_KEY_PATH,
        help=f"Archivo de clave (por defecto: {DEFAULT_KEY_PATH}).",
    )

    p = sub.add_parser("generate-key", parents=[algo], help="Genera una clave aleatoria segura.")
    p.add_argument("--output", "-o", type=Path, default=DEFAULT_KEY_PATH,
                   help=f"Dónde guardar la clave (por defecto: {DEFAULT_KEY_PATH}).")
    p.add_argument("--force", action="store_true", help="Sobrescribir una clave existente.")
    p.set_defaults(handler=_cmd_generate_key)

    p = sub.add_parser("encrypt", parents=[algo, key_opt], help="Cifra un archivo.")
    p.add_argument("file", type=Path, help="Archivo a cifrar.")
    p.add_argument("--output", "-o", type=Path, help="Destino (por defecto: <archivo>.enc).")
    p.add_argument("--force", action="store_true", help="Sobrescribir el destino si existe.")
    p.set_defaults(handler=_cmd_encrypt)

    p = sub.add_parser("decrypt", parents=[key_opt], help="Verifica y descifra un archivo .enc.")
    p.add_argument("file", type=Path, help="Archivo .enc a descifrar.")
    p.add_argument("--output", "-o", type=Path, help="Destino (por defecto: sin la extensión .enc).")
    p.add_argument("--force", action="store_true", help="Sobrescribir el destino si existe.")
    p.set_defaults(handler=_cmd_decrypt)

    p = sub.add_parser("inspect", help="Muestra metadatos no sensibles de un archivo .enc.")
    p.add_argument("file", type=Path, help="Archivo .enc a inspeccionar.")
    p.set_defaults(handler=_cmd_inspect)

    p = sub.add_parser("algorithms", help="Lista los algoritmos registrados.")
    p.set_defaults(handler=_cmd_algorithms)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Punto de entrada. Devuelve el código de salida del proceso."""
    _configure_output_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except AuthenticationError as exc:
        _error(str(exc))
        return EXIT_AUTH_FAILURE
    except CryptoAgilityError as exc:
        _error(str(exc))
        return EXIT_ERROR
    except KeyboardInterrupt:
        _error("Operación cancelada por el usuario.")
        return 130
    except OSError as exc:
        _error(f"Error de entrada/salida: {exc.strerror or exc}")
        return EXIT_ERROR
