#!/bin/bash
[[ -d .venv ]] && source .venv/bin/activate

uvicorn inge-6.main:app --reload --host 0.0.0.0 --port 8006
