#!/bin/bash
# run.sh — Inicia el servidor POODLE demo en un entorno virtual
set -e

VENV=".venv"

if [ ! -d "$VENV" ]; then
    echo "[*] Creando entorno virtual..."
    python3 -m venv "$VENV"
fi

echo "[*] Activando entorno virtual..."
source "$VENV/bin/activate"

echo "[*] Instalando dependencias..."
pip install -q -r requirements.txt

echo "[*] Iniciando servidor en http://0.0.0.0:5000"
python3 server.py
