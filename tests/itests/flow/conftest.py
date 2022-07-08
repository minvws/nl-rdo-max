import pytest
import os
import sys
import threading
import time
from multiprocessing import Process

import inge6.main
import inge6.config

import uvicorn

import asyncio


@pytest.fixture
def max_application(redis_mock):
    """
    We should build support to use a different config for test setup, but at this moment this is not possible
    """
    uvicorn_args = {"host": "127.0.0.1", "port": 48123, "log_level": "info"}
    proc = Process(
        target=uvicorn.run, args=("inge6.main:app",), kwargs=uvicorn_args, daemon=False
    )
    proc.start()
    time.sleep(1)
    yield f"http://{uvicorn_args['host']}:{uvicorn_args['port']}"
    proc.kill()
