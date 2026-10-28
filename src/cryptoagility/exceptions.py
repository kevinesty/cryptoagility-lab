"""Excepciones propias del proyecto.

Todas heredan de :class:`CryptoAgilityError`, de modo que la CLI puede capturarlas
en un único punto y mostrar mensajes claros sin volcar trazas al usuario.
Ningún mensaje de error debe incluir nunca material de clave.
"""

from __future__ import annotations


class CryptoAgilityError(Exception):
    """Error base de la aplicación."""


class InvalidKeyError(CryptoAgilityError):
    """La clave tiene un tamaño o tipo incorrecto para el algoritmo."""


class KeyFileError(CryptoAgilityError):
    """No se pudo leer, escribir o interpretar un archivo de clave."""


class AuthenticationError(CryptoAgilityError):
    """Falló la verificación de autenticidad/integridad (clave incorrecta o datos alterados)."""


class InvalidFileFormatError(CryptoAgilityError):
    """El archivo no tiene el formato esperado (firma, cabecera o longitud inválidas)."""


class UnsupportedVersionError(InvalidFileFormatError):
    """La versión del formato del archivo no está soportada por esta instalación."""


class UnsupportedAlgorithmError(CryptoAgilityError):
    """El algoritmo solicitado o indicado en el archivo no está registrado."""


class FileOperationError(CryptoAgilityError):
    """Problema de entrada/salida: archivo inexistente, sin permisos, ya existente, etc."""


class ConfigError(CryptoAgilityError):
    """Configuración inválida."""
