"""Ejemplo de uso programático (como biblioteca) de CryptoAgility Lab.

Ejecutar desde la raíz del repositorio:

    python examples/example_usage.py

Todo ocurre en un directorio temporal que se elimina al terminar; no se dejan
claves ni archivos cifrados en el repositorio.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from cryptoagility.encryption import get_cipher  # noqa: E402
from cryptoagility.exceptions import AuthenticationError  # noqa: E402
from cryptoagility.key_manager import load_key, save_key  # noqa: E402
from cryptoagility.service import decrypt_file, encrypt_file, inspect_file  # noqa: E402


def main() -> None:
    sample = Path(__file__).with_name("sample.txt")
    provider = get_cipher("aes-256-gcm")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        # La clave se guarda en una carpeta distinta a la de los datos cifrados.
        key_path = save_key(provider.generate_key(), work / "claves" / "demo.key")
        key = load_key(key_path)

        (work / "datos").mkdir()
        encrypted = encrypt_file(sample, key, work / "datos" / "sample.txt.enc")

        info = inspect_file(encrypted)
        print(f"Cifrado: {encrypted.name} -> {info.algorithm_name}, versión {info.format_version}")

        restored = decrypt_file(encrypted, key, work / "datos" / "restaurado.txt")
        print("Descifrado correcto:", restored.read_bytes() == sample.read_bytes())

        # Simulamos una alteración del archivo cifrado.
        data = bytearray(encrypted.read_bytes())
        data[-1] ^= 0x01
        encrypted.write_bytes(bytes(data))
        try:
            decrypt_file(encrypted, key, work / "datos" / "no_debe_existir.txt")
        except AuthenticationError as exc:
            print("Alteración detectada:", exc)
        print("¿Se creó salida parcial?", (work / "datos" / "no_debe_existir.txt").exists())


if __name__ == "__main__":
    main()
