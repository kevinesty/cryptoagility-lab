# Cómo añadir un algoritmo sin reescribir la aplicación

Gracias a la arquitectura modular, añadir un algoritmo AEAD requiere **una clase y un registro**. No hay que tocar `service.py`, `file_format.py` ni `cli.py`.

## Pasos

1. **Implementar `CipherProvider`** con un `name` único, un `algorithm_id` nuevo (**nunca reutilizar** uno existente) y los tamaños de clave, nonce y etiqueta.
2. **Registrarlo** con `register_cipher(...)` (en `encryption.py`, junto al de AES-GCM, o en un módulo/plugin propio).
3. **Seleccionarlo** con `--algorithm`, `CRYPTOAGILITY_ALGORITHM` o el JSON de configuración.
4. **Probar**: cifrado/descifrado, clave incorrecta, manipulación, y *known-answer tests* si el estándar publica vectores.

Los archivos antiguos siguen descifrándose porque la cabecera lleva el `algorithm_id` con el que se crearon.

## Ejemplo real: ChaCha20-Poly1305

Usa la misma biblioteca `cryptography`; **no se inventa ninguna primitiva**. Este código ya está en `tests/test_agility.py` y se ejecuta en las pruebas:

```python
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from cryptoagility.encryption import CipherProvider, register_cipher
from cryptoagility.exceptions import AuthenticationError


class ChaCha20Poly1305Provider(CipherProvider):
    name = "chacha20-poly1305"
    algorithm_id = 2          # nuevo id, jamás reutilizado
    key_size = 32
    nonce_size = 12
    tag_size = 16

    def encrypt(self, key, nonce, plaintext, associated_data):
        self.validate_key(key)
        self.validate_nonce(nonce)
        return ChaCha20Poly1305(bytes(key)).encrypt(nonce, plaintext, associated_data)

    def decrypt(self, key, nonce, ciphertext, associated_data):
        self.validate_key(key)
        self.validate_nonce(nonce)
        try:
            return ChaCha20Poly1305(bytes(key)).decrypt(nonce, ciphertext, associated_data)
        except InvalidTag:
            raise AuthenticationError("Autenticación fallida.") from None


register_cipher(ChaCha20Poly1305Provider())
```

Con eso, `python main.py encrypt archivo.txt -a chacha20-poly1305` funciona y `decrypt` detecta el algoritmo por sí solo.

> ChaCha20-Poly1305 **no está registrado por defecto** en la aplicación: el proyecto inicial incluye únicamente AES-256-GCM. El ejemplo existe para demostrar la extensibilidad.

## Qué pasa con la criptografía poscuántica

**No está implementada.** Los algoritmos poscuánticos estandarizados por NIST (p. ej. ML-KEM, FIPS 203) no son cifradores de archivos: son mecanismos de **encapsulado de claves**. Integrarlos no encaja en la interfaz `CipherProvider` (que cifra datos con una clave simétrica ya conocida) y requeriría:

- una nueva abstracción (`KeyEncapsulation`) que produzca o proteja la clave simétrica de cada archivo,
- una **versión 2 del formato** que almacene el material encapsulado,
- preferiblemente un esquema **híbrido** (clásico + poscuántico) y bibliotecas auditadas.

La agilidad criptográfica del proyecto (versión y algoritmo en la cabecera, capas desacopladas) hace posible esa evolución, pero **hoy no existe**.
