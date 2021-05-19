#!/bin/bash
[[ -d .venv ]] && source .venv/bin/activate

uvicorn inge-6.main:app --reload --host 127.0.0.1 --port 8006
