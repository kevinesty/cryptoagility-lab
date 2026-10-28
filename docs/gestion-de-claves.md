# Gestión de claves

> Proyecto educativo: estas prácticas son un punto de partida, no un sistema de gestión de claves de nivel producción.

## Qué hace el proyecto

- Genera claves con `secrets.token_bytes` (CSPRNG del sistema operativo): 32 bytes = 256 bits para AES-256.
- Las guarda en un archivo **separado** del archivo cifrado (por defecto `keys/default.key`), en Base64.
- Crea el archivo con permisos `0600` en POSIX y **rechaza sobrescribir** una clave existente salvo `--force`.
- **No imprime** la clave, **no la registra** y **no la incluye en mensajes de error** (probado automáticamente).
- Avisa si la clave está en la misma carpeta que el archivo y si sus permisos son demasiado abiertos (POSIX).
- `keys/`, `*.key` y `*.enc` están en `.gitignore` para evitar subirlos a GitHub.

## Riesgos de guardar la clave junto al archivo cifrado

- **Anula el cifrado:** quien consiga el archivo consigue la clave. Es "cerrar con llave y dejar la llave en la cerradura".
- **Copias conjuntas:** copias de seguridad, carpetas sincronizadas, adjuntos o repositorios suelen llevarse la carpeta completa.
- **Falsa sensación de seguridad:** el sistema parece protegido y no lo está.
- **Un único punto de compromiso:** un solo robo expone clave y datos.

## Recomendaciones de protección

1. **Almacenar la clave en otro lugar** que los datos: gestor de contraseñas, almacén de secretos del sistema, dispositivo externo cifrado o, en entornos reales, KMS/HSM.
2. **Restringir el acceso**: permisos mínimos; en Windows, comprobar las ACL de la carpeta `keys/`.
3. **No transmitir clave y archivo por el mismo canal.**
4. **No incluir nunca claves en Git**, capturas de pantalla, tickets, correos o chats. Si una clave se sube por error, considérala comprometida: rótala.
5. **Una clave por finalidad/conjunto de datos** para limitar el daño de un compromiso.
6. **Rotación:** en uso real, sustituir claves periódicamente y re-cifrar (no implementado aquí).

## Recomendaciones de respaldo

- **Si pierdes la clave, los datos son irrecuperables.** No existe puerta trasera.
- Mantén **al menos dos copias** en ubicaciones físicas o lógicas distintas.
- Protege las copias con el mismo rigor que la original (no sirve de nada un respaldo en claro en una carpeta compartida).
- **Prueba la restauración** periódicamente: descifra un archivo de prueba con la copia de la clave.
- Documenta qué clave corresponde a qué datos (el formato actual no guarda identificador de clave).

## Limitaciones conocidas

- Base64 es una codificación, **no cifrado**: el archivo de clave está en claro en disco.
- En Python no se puede borrar de forma garantizada un secreto de la memoria.
- En Windows el modo `0600` apenas tiene efecto.
- No hay derivación de clave desde contraseña (scrypt/Argon2id), ni envolvimiento de claves, ni integración con KMS: todo ello figura en las mejoras futuras.
