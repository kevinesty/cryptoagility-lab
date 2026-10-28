"""Pruebas de la selección de algoritmo por configuración."""

from __future__ import annotations

import pytest

from cryptoagility.config import ENV_VAR, load_config
from cryptoagility.exceptions import ConfigError, UnsupportedAlgorithmError


def test_default():
    assert load_config(env={}).algorithm == "aes-256-gcm"


def test_file_config(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"algorithm": "AES-256-GCM"}')
    assert load_config(cfg, env={}).algorithm == "aes-256-gcm"


def test_env_overrides_file(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"algorithm": "aes-256-gcm"}')
    with pytest.raises(UnsupportedAlgorithmError):
        load_config(cfg, env={ENV_VAR: "no-existe"})


def test_cli_overrides_env():
    assert load_config(cli_algorithm="aes-256-gcm", env={ENV_VAR: "no-existe"}).algorithm == "aes-256-gcm"


def test_unknown_algorithm_rejected():
    with pytest.raises(UnsupportedAlgorithmError):
        load_config(cli_algorithm="des", env={})


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match="No se encontró"):
        load_config(tmp_path / "no.json", env={})


def test_invalid_json(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text("{no es json")
    with pytest.raises(ConfigError):
        load_config(cfg, env={})


def test_non_object_json(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text("[1, 2]")
    with pytest.raises(ConfigError, match="objeto JSON"):
        load_config(cfg, env={})


def test_unknown_keys_rejected(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"algoritm": "aes-256-gcm"}')  # errata deliberada
    with pytest.raises(ConfigError, match="desconocidas"):
        load_config(cfg, env={})


def test_non_string_algorithm(tmp_path):
    cfg = tmp_path / "c.json"
    cfg.write_text('{"algorithm": 256}')
    with pytest.raises(ConfigError, match="cadena"):
        load_config(cfg, env={})
