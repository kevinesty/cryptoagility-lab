"""Punto de entrada: ``python main.py <comando>``.

Añade ``src/`` al path para poder ejecutarse sin instalar el paquete.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from cryptoagility.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
