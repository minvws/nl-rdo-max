#!/bin/bash
[[ -d .venv ]] && source .venv/bin/activate

#uvicorn inge-6.main:app --reload --host 0.0.0.0 --port 8006
python3 -m inge-6.main
