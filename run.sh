#!/bin/bash

# Move to the directory of this script
cd "$(dirname "$0")"

# 1. Setup virtualenv if not existing
if [ ! -d "venv" ]; then
    echo "[!] No se encontro el entorno virtual 'venv'. Creándolo ahora..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "[ERROR] Fallo al crear venv. Asegurate de tener python3-venv instalado."
        exit 1
    fi
    echo "[*] Instalando dependencias desde requirements.txt..."
    ./venv/bin/pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[ERROR] Fallo al instalar dependencias."
        exit 1
    fi
fi

# 2. Check privileges
if [ "$EUID" -ne 0 ]; then
    echo "[!] TCPspecter funciona mejor con privilegios de Administrador (sudo)."
    echo "[!] Si no usas sudo, no podras ver sockets/procesos de otros usuarios ni terminar ciertos procesos."
    echo ""
    read -p "¿Deseas re-ejecutar la aplicacion usando 'sudo'? (S/n): " choice
    case "$choice" in
        [nN][nN]|[nN])
            echo "[*] Iniciando en modo usuario (sin sudo)..."
            ./venv/bin/python3 app.py
            ;;
        *)
            echo "[*] Solicitando elevacion con sudo..."
            exec sudo ./venv/bin/python3 app.py
            ;;
    esac
else
    # Running as root, execute directly using the venv python
    exec ./venv/bin/python3 app.py
fi
