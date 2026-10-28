"""Pruebas de la interfaz de línea de comandos (código de salida y mensajes)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from cryptoagility.cli import EXIT_AUTH_FAILURE, EXIT_ERROR, EXIT_OK, main
from cryptoagility.key_manager import encode_key, load_key

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def workdir(tmp_path, monkeypatch):
    """Directorio de trabajo aislado con un archivo y la clave en carpetas separadas."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "datos").mkdir()
    (tmp_path / "datos" / "nota.txt").write_text("contenido de prueba\n")
    return tmp_path


def test_generate_key_creates_file_and_never_prints_it(workdir, capsys):
    assert main(["generate-key", "-o", "keys/k.key"]) == EXIT_OK
    out = capsys.readouterr()
    key = load_key(workdir / "keys" / "k.key")
    assert len(key) == 32
    assert encode_key(key) not in out.out + out.err
    assert key.hex() not in out.out + out.err
    assert "NO se muestra" in out.out


def test_generate_key_refuses_overwrite_unless_forced(workdir, capsys):
    assert main(["generate-key", "-o", "keys/k.key"]) == EXIT_OK
    original = (workdir / "keys" / "k.key").read_bytes()
    assert main(["generate-key", "-o", "keys/k.key"]) == EXIT_ERROR
    assert "ya existe" in capsys.readouterr().err
    assert (workdir / "keys" / "k.key").read_bytes() == original
    assert main(["generate-key", "-o", "keys/k.key", "--force"]) == EXIT_OK
    assert (workdir / "keys" / "k.key").read_bytes() != original


def test_full_flow(workdir, capsys):
    main(["generate-key", "-o", "keys/k.key"])
    assert main(["encrypt", "datos/nota.txt", "-k", "keys/k.key"]) == EXIT_OK
    assert (workdir / "datos" / "nota.txt.enc").is_file()
    (workdir / "datos" / "nota.txt").unlink()
    assert main(["decrypt", "datos/nota.txt.enc", "-k", "keys/k.key"]) == EXIT_OK
    assert (workdir / "datos" / "nota.txt").read_text() == "contenido de prueba\n"
    assert "verificadas" in capsys.readouterr().out


def test_default_key_path(workdir):
    assert main(["generate-key"]) == EXIT_OK
    assert (workdir / "keys" / "default.key").is_file()
    assert main(["encrypt", "datos/nota.txt"]) == EXIT_OK


def test_decrypt_with_wrong_key_exit_code_and_message(workdir, capsys):
    main(["generate-key", "-o", "keys/a.key"])
    main(["generate-key", "-o", "keys/b.key"])
    main(["encrypt", "datos/nota.txt", "-k", "keys/a.key"])
    (workdir / "datos" / "nota.txt").unlink()
    capsys.readouterr()
    code = main(["decrypt", "datos/nota.txt.enc", "-k", "keys/b.key"])
    assert code == EXIT_AUTH_FAILURE
    err = capsys.readouterr().err
    assert "Autenticación fallida" in err
    assert not (workdir / "datos" / "nota.txt").exists()


def test_decrypt_tampered_file(workdir, capsys):
    main(["generate-key", "-o", "keys/a.key"])
    main(["encrypt", "datos/nota.txt", "-k", "keys/a.key"])
    enc = workdir / "datos" / "nota.txt.enc"
    raw = bytearray(enc.read_bytes())
    raw[-1] ^= 0xFF
    enc.write_bytes(bytes(raw))
    (workdir / "datos" / "nota.txt").unlink()
    assert main(["decrypt", str(enc), "-k", "keys/a.key"]) == EXIT_AUTH_FAILURE
    assert not (workdir / "datos" / "nota.txt").exists()


def test_encrypt_nonexistent_file(workdir, capsys):
    main(["generate-key", "-o", "keys/k.key"])
    assert main(["encrypt", "fantasma.txt", "-k", "keys/k.key"]) == EXIT_ERROR
    assert "no existe" in capsys.readouterr().err


def test_encrypt_without_key_file(workdir, capsys):
    assert main(["encrypt", "datos/nota.txt", "-k", "keys/no.key"]) == EXIT_ERROR
    assert "generate-key" in capsys.readouterr().err
    assert not (workdir / "datos" / "nota.txt.enc").exists()


def test_inspect_output(workdir, capsys):
    main(["generate-key", "-o", "keys/k.key"])
    main(["encrypt", "datos/nota.txt", "-k", "keys/k.key"])
    key_text = encode_key(load_key(workdir / "keys" / "k.key"))
    capsys.readouterr()
    assert main(["inspect", "datos/nota.txt.enc"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "aes-256-gcm" in out
    assert "versión 1" in out
    assert "NO verifica la integridad" in out
    assert key_text not in out


def test_inspect_invalid_file(workdir, capsys):
    (workdir / "datos" / "falso.enc").write_bytes(b"nada que ver aqui")
    assert main(["inspect", "datos/falso.enc"]) == EXIT_ERROR
    assert "Error:" in capsys.readouterr().err


def test_algorithms_command(capsys):
    assert main(["algorithms"]) == EXIT_OK
    assert "aes-256-gcm" in capsys.readouterr().out


def test_unknown_algorithm_option(workdir, capsys):
    assert main(["generate-key", "-o", "keys/k.key", "-a", "rot13"]) == EXIT_ERROR
    assert "no soportado" in capsys.readouterr().err


def test_warns_when_key_next_to_data(workdir, capsys):
    main(["generate-key", "-o", "datos/k.key"])
    capsys.readouterr()
    assert main(["encrypt", "datos/nota.txt", "-k", "datos/k.key"]) == EXIT_OK
    assert "misma carpeta" in capsys.readouterr().err


def test_no_command_is_usage_error(capsys):
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_help_and_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "1.0.0" in capsys.readouterr().out


def _run_main_py(cwd: Path, *args: str, io_encoding: str = "utf-8") -> subprocess.CompletedProcess[str]:
    """Ejecuta ``main.py`` como proceso real con una codificación de E/S EXPLÍCITA.

    Sin fijar ``PYTHONIOENCODING``, el hijo escribe en la codificación del sistema
    (cp1252 en Windows al usar tuberías) mientras el padre decodifica en UTF-8: el
    byte 0xE1 de la "á" provocaba ``UnicodeDecodeError`` en el hilo lector de
    ``subprocess`` (``PytestUnhandledThreadExceptionWarning``). Aquí ambos lados
    acuerdan la codificación y se decodifica en modo estricto (sin ``errors=``).
    """
    env = {**os.environ, "PYTHONIOENCODING": io_encoding}
    return subprocess.run(
        [sys.executable, str(ROOT / "main.py"), *args],
        cwd=cwd, capture_output=True, text=True, encoding=io_encoding, env=env,
    )


def test_main_py_smoke_end_to_end(tmp_path):
    """Ejecuta main.py como proceso real, igual que lo haría el usuario."""
    src = tmp_path / "hola.txt"
    src.write_text("hola mundo")

    generated = _run_main_py(tmp_path, "generate-key", "-o", "claves/k.key")
    assert generated.returncode == 0, generated.stderr
    # Comprueba que los caracteres no ASCII viajan y se decodifican correctamente.
    assert "Guárdala" in generated.stdout

    encrypted = _run_main_py(tmp_path, "encrypt", "hola.txt", "-k", "claves/k.key")
    assert encrypted.returncode == 0, encrypted.stderr
    src.unlink()
    done = _run_main_py(tmp_path, "decrypt", "hola.txt.enc", "-k", "claves/k.key")
    assert done.returncode == 0, done.stderr
    assert src.read_text() == "hola mundo"


@pytest.mark.parametrize("io_encoding", ["cp1252", "ascii"])
def test_cli_survives_any_output_encoding(tmp_path, io_encoding):
    """La salida no debe provocar un traceback aunque la consola no soporte las tildes.

    Regresión: con codificación ASCII, ``generate-key`` fallaba con
    ``UnicodeEncodeError`` DESPUÉS de haber guardado la clave.
    """
    result = _run_main_py(tmp_path, "generate-key", "-o", "k.key", io_encoding=io_encoding)
    assert result.returncode == 0, result.stderr
    assert "Traceback" not in result.stderr
    assert (tmp_path / "k.key").is_file()
    assert "256 bits" in result.stdout
