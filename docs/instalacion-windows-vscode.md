# Instalación y ejecución en Windows con Visual Studio Code

## 0. Requisitos previos

1. **Python 3.11 o superior**: descárgalo de <https://www.python.org/downloads/> y, en el instalador, marca **"Add python.exe to PATH"**. Comprueba en PowerShell:
   ```powershell
   python --version
   ```
   (Si `python` no funciona, prueba `py --version`; el lanzador `py` suele estar instalado.)
2. **Git**: <https://git-scm.com/download/win>. Comprueba: `git --version`.
3. **Visual Studio Code** y, dentro, la extensión **Python** (de Microsoft).

## 1. Abrir el proyecto

1. Descomprime el proyecto (o clónalo) en una carpeta, por ejemplo `C:\Users\TuUsuario\Proyectos\cryptoagility-lab`.
2. En VS Code: **Archivo → Abrir carpeta…** y elige `cryptoagility-lab`.
3. Abre la terminal integrada: **Ctrl + `** (o *Terminal → Nuevo terminal*). Debe ser **PowerShell** y estar en la carpeta del proyecto.

## 2. Crear y activar el entorno virtual

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Verás `(.venv)` al inicio del prompt.

> **Si PowerShell bloquea el script** ("la ejecución de scripts está deshabilitada"):
> ```powershell
> Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
> ```
> y vuelve a activar. Alternativa sin cambiar políticas: usa *Símbolo del sistema* y ejecuta `.venv\Scripts\activate.bat`.

Selecciona el intérprete en VS Code: **Ctrl+Shift+P → "Python: Select Interpreter" → `.venv`**.

## 3. Instalar dependencias

```powershell
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
```

## 4. Ejecutar las pruebas

```powershell
python -m pytest -v
```

Resultado esperado: **138 passed**.

Desde VS Code: icono del matraz (*Testing*) → **Configure Python Tests → pytest → carpeta `tests`**.

## 5. Probar el cifrado paso a paso

```powershell
# 1) Crear un archivo de prueba (sin datos reales)
Set-Content -Path prueba.txt -Value "Texto de prueba para CryptoAgility Lab"

# 2) Generar una clave (queda en keys\default.key; no se muestra en pantalla)
python main.py generate-key

# 3) Cifrar -> crea prueba.txt.enc (el original no se toca)
python main.py encrypt prueba.txt

# 4) Ver metadatos no sensibles
python main.py inspect prueba.txt.enc

# 5) Descifrar a otro nombre y comparar hashes
python main.py decrypt prueba.txt.enc -o prueba.restaurado.txt
Get-FileHash -Algorithm SHA256 prueba.txt, prueba.restaurado.txt
```

Los dos hashes SHA-256 deben ser idénticos.

### Probar la detección de manipulación

```powershell
# Alterar el último byte (la etiqueta de autenticación) del archivo cifrado
$bytes = [System.IO.File]::ReadAllBytes("$PWD\prueba.txt.enc")
$bytes[$bytes.Length - 1] = $bytes[$bytes.Length - 1] -bxor 1
[System.IO.File]::WriteAllBytes("$PWD\prueba.txt.enc", $bytes)

python main.py decrypt prueba.txt.enc -o salida.txt
# -> Error: Autenticación fallida ...   (y NO se crea salida.txt)
Test-Path salida.txt     # False
$LASTEXITCODE            # 3
```

### Probar una clave incorrecta

```powershell
python main.py generate-key -o keys\otra.key
python main.py encrypt prueba.txt -o prueba2.enc --force
python main.py decrypt prueba2.enc -k keys\otra.key -o x.txt   # -> error de autenticación
```

### Ejemplo programático

```powershell
python examples\example_usage.py
```

## 6. Subir el proyecto a GitHub

1. En <https://github.com/new> crea un repositorio **vacío** llamado `cryptoagility-lab` (sin README, sin .gitignore, sin licencia: ya los trae el proyecto).
2. En la terminal, dentro de la carpeta del proyecto:

```powershell
# Identidad (solo la primera vez en tu equipo)
git config --global user.name "Tu Nombre"
git config --global user.email "tu-correo@ejemplo.com"

git init
git add .

# Comprobaciones de seguridad ANTES de confirmar: no debe salir ninguna clave ni .enc
git status
git ls-files | Select-String -Pattern "\.key$|\.enc$|\.env"
git check-ignore -v keys/default.key

git commit -m "feat: CryptoAgility Lab - cifrado AES-256-GCM y agilidad criptografica"
git branch -M main
git remote add origin https://github.com/TU_USUARIO/cryptoagility-lab.git
git push -u origin main
```

Si `git ls-files | Select-String ...` no muestra nada y `check-ignore` confirma que `keys/default.key` está ignorado, es seguro subirlo.

3. Antes de publicar, edita `LICENSE` (sustituye `<TU NOMBRE>`) y los enlaces `TU_USUARIO` del README.
4. En GitHub, pestaña **Actions**: el flujo `Tests` ejecutará las pruebas en Windows y Linux (Python 3.11 y 3.12).

### Si alguna vez subes una clave por error

Considérala **comprometida**: genera una nueva, re-cifra tus datos y no te limites a borrarla de un commit posterior (queda en el historial).

## Problemas frecuentes

| Síntoma | Solución |
|---|---|
| `python` no se reconoce | Reinstala Python marcando *Add to PATH* o usa `py -3.11 -m venv .venv` |
| No se puede activar el entorno | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` o usa `activate.bat` |
| `ModuleNotFoundError: cryptography` | Activa el `.venv` y ejecuta `pip install -r requirements-dev.txt` |
| `ModuleNotFoundError: cryptoagility` en pytest | Ejecuta desde la raíz del proyecto con `python -m pytest` |
| VS Code no detecta el entorno | *Python: Select Interpreter* → `.venv` |
