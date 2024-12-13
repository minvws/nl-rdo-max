import os
from typing import Any

import inject
from fastapi import Depends
from inject import Injectable


def root_path(*args: str) -> str:
    """
    Returns the absolute path to a file or directory relative to the project root.

    Args:
        *args (str): Any number of path components as strings. These will be joined
                     together to form the final path relative to the project root.

    Returns:
        str: Absolute path to the specified file or directory relative to the project root.
    """
    return os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", *args),
    )


def resolve_instance(cls: Any) -> Any:
    """
    Resolves an instance using the `inject` dependency injection package for integration
    with FastAPI's dependency injection system.

    Use this function in places where you would normally use FastAPI's `Depends()` but
    want to resolve a dependency using the more powerful `inject` package.
    """

    def get_instance() -> Injectable:
        return inject.instance(cls)

    return Depends(get_instance)
