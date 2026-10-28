# Cómo explicar el proyecto en una entrevista

## Qué conceptos demuestra

| Área | Qué demuestras |
|---|---|
| **Criptografía simétrica y AEAD** | Sabes que cifrar no basta: hace falta autenticar. Entiendes AES-GCM (CTR + GHASH), nonce, etiqueta y AAD. |
| **Uso correcto de primitivas** | Usas una biblioteca reconocida, no inventas algoritmos, generas nonces/claves con CSPRNG y conoces el riesgo de reutilizar un nonce. |
| **Integridad y autenticidad** | "Verificar antes de usar": no se escribe texto plano si la etiqueta falla. Detección de manipulación probada. |
| **Gestión de claves** | Separación clave/datos, no hardcodear, no loguear, permisos, respaldo y por qué una clave junto al dato anula el cifrado. |
| **Agilidad criptográfica** | Abstracción, registro, versión e id de algoritmo en el formato, compatibilidad hacia atrás. |
| **Diseño de formatos y protocolos** | Cabecera versionada, validación estricta, datos asociados autenticados. |
| **Ingeniería segura** | Errores que no filtran secretos, escritura atómica, no sobrescribir por defecto, fallar de forma segura. |
| **Modelo de amenazas** | Sabes qué protege y qué **no** (robo de clave, malware, metadatos, rollback). |
| **Calidad de software** | Python tipado, modular, 138 pruebas, vectores oficiales, CI en Windows y Linux. |
| **Honestidad técnica** | Limitaciones explícitas; no afirmas criptografía poscuántica. |

## Pitch de 60-90 segundos

> "Desarrollé CryptoAgility Lab, un laboratorio en Python para cifrar archivos con AES-256-GCM usando la biblioteca `cryptography`. No implementé ningún algoritmo propio; el objetivo era usar bien las primitivas. Cada cifrado genera un nonce aleatorio de 96 bits, y la cabecera del archivo, con versión, algoritmo y nonce, se autentica como datos asociados, de modo que cualquier modificación, o una clave incorrecta, se detecta y no se escribe ningún archivo descifrado. La clave se guarda separada del archivo cifrado y nunca se imprime ni se registra. Diseñé la arquitectura con una interfaz `CipherProvider` y un registro de algoritmos, y guardo el id del algoritmo en la cabecera, así que se puede cambiar o añadir algoritmos sin reescribir la aplicación y seguir leyendo archivos antiguos; lo demuestro en las pruebas con ChaCha20-Poly1305. Tengo 138 pruebas, incluidos vectores oficiales de GCM, y documenté el modelo de amenazas y las limitaciones: por ejemplo, no es poscuántico, no hay derivación de clave desde contraseña y no está auditado."

## Preguntas probables y respuestas guía

**¿Por qué GCM y no CBC o ECB?**
ECB filtra patrones. CBC da confidencialidad pero no integridad: hay que añadir un MAC (y hacerlo bien, *encrypt-then-MAC*) y es vulnerable a *padding oracles* si se implementa mal. GCM es AEAD: cifra y autentica en una sola operación estándar.

**¿Qué pasa si se reutiliza un nonce en GCM?**
Con la misma clave, dos mensajes cifrados con el mismo nonce revelan el XOR de los textos planos y permiten recuperar la clave de autenticación (GHASH), con lo que se pueden falsificar mensajes. Por eso el nonce es aleatorio y distinto en cada cifrado (con aleatorios, el límite recomendado es 2³² cifrados por clave).

**¿Por qué el nonce va en claro dentro del archivo?**
No es secreto; solo debe ser único. El descifrado lo necesita.

**¿Para qué sirve el AAD?**
Autentica datos que no se cifran. Aquí, la cabecera: así no se puede cambiar el algoritmo, la versión o el nonce sin que falle la verificación.

**¿Cómo distingues clave incorrecta de archivo manipulado?**
No se distingue, ni conviene: ambos hacen fallar la etiqueta y dar detalles ayudaría a un atacante. El mensaje cubre ambos casos.

**¿Por qué no guardar la clave junto al archivo?**
Porque quien obtenga el archivo obtiene la clave; el cifrado no aporta nada. Es un error de gestión de claves muy común.

**¿Qué es la agilidad criptográfica y por qué importa?**
Poder sustituir algoritmos sin rediseñar el sistema. Importa porque los algoritmos se debilitan o se deprecian (MD5, SHA-1, 3DES) y porque se avecinan migraciones, como la poscuántica. Aquí: interfaz, registro, id de algoritmo y versión en la cabecera, y selección por configuración.

**¿Tu proyecto es poscuántico?**
No, y lo digo explícitamente. AES-256 se considera con buen margen frente a Grover, pero la parte poscuántica relevante (ML-KEM, FIPS 203) es de encapsulado de claves y exigiría otra capa y un formato v2 híbrido. La arquitectura lo facilita, pero no está implementado.

**¿Cómo lo mejorarías?**
Streaming por bloques para archivos grandes; derivación de clave desde contraseña con scrypt/Argon2id; *envelope encryption* con clave maestra; identificador y rotación de claves; integración con KMS; protección contra *rollback*; formato v2 híbrido.

**¿Qué diferencia hay entre hash, MAC, cifrado y firma?**
Hash: huella sin clave (integridad solo frente a errores accidentales). MAC: integridad y autenticidad con clave compartida. Cifrado: confidencialidad. Firma digital: integridad, autenticidad y no repudio con clave asimétrica. AEAD combina cifrado y MAC.

**¿Cómo sabes que funciona?**
Pruebas automatizadas: ida y vuelta con tamaños de 0 B a 5 MiB, clave incorrecta, manipulación de cada zona del archivo, truncado, archivos inexistentes y vacíos, ausencia de salida parcial, y *known-answer tests* con vectores oficiales de AES-256-GCM.

**¿Qué amenazas NO cubre?**
Robo de la clave, malware en el equipo, ocultación de metadatos, *rollback* a una versión antigua válida, disponibilidad (pérdida del archivo o de la clave) y borrado seguro del original.

## Consejos para la demostración en directo

1. Genera una clave, cifra un archivo y muestra con `inspect` que ahí no hay claves.
2. Abre el `.enc` en un editor hexadecimal: ve la firma `CAGL`, la versión y el nonce, y el resto es ruido.
3. Modifica un solo byte y muestra que `decrypt` falla con código 3 y que **no** aparece ningún archivo.
4. Enseña `tests/test_agility.py`: un segundo algoritmo sin tocar la aplicación.
5. Termina con el modelo de amenazas y las limitaciones: demuestra criterio.
