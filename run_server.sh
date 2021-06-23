#!/bin/bash
#
# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#

[[ -d .venv ]] && source .venv/bin/activate

#uvicorn inge-6.main:app --reload --host 0.0.0.0 --port 8006
python3 -m inge6.main
