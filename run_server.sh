#!/bin/bash
[[ -d .venv ]] && source .venv/bin/activate

export PYTHON_SETTINGS_MODULE="inge6.runtime.settings"
python3 -m inge6.main
