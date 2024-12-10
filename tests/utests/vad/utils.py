from typing import Callable

from fastapi import FastAPI
import inject
from inject import Binder

from app.vad import config
from app.vad.bindings import configure_bindings as configure_app_bindings
from app.vad.config.schemas import Config
from app.vad.utils import root_path
from app.dependency_injection.config import get_config


def configure_bindings(
    bindings_override: Callable[[Binder], Binder] | None = None,
) -> None:
    """
    Configures dependency injection bindings for the application.

    Sets up standard bindings using `vad.conf.test`.
    If `bindings_override` is provided, it overrides bindings over other bindings.
    """

    def bindings_config(binder: inject.Binder) -> None:
        binder.install(
            lambda binder: configure_app_bindings(binder, config_file="vad.conf.test")
        )

        if bindings_override:
            bindings_override(binder)

    inject.configure(bindings_config, clear=True, allow_override=True)


def clear_bindings() -> None:
    inject.clear()


def load_app_config() -> Config:
    if not inject.is_configured():
        configure_bindings()

    app_config: Config = inject.instance(Config)
    return app_config
