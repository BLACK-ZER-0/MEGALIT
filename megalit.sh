#!/usr/bin/env bash
# Megalit launcher (Linux / macOS / Kali):  ./megalit.sh example.com
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}"
exec python3 "$DIR/megalit.py" "$@"
