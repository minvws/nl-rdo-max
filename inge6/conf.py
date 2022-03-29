"""Exposes the settings declared in the environment variable
``PYTHON_SETTINGS_MODULE``."""
import contextlib
import functools
import importlib
import inspect
import itertools
import types
import os
import sys


DEPLOYMENT_ENV = os.getenv('DEPLOYMENT_ENV')


class Settings:
    """Proxy object to load settings lazily."""

    @staticmethod
    def import_settings(qualname):
        """Import `qualname` and construct a module based on the value of
        :envvar:`DEPLOYMENT_ENV`.
        """
        settings = types.ModuleType('settings')
        if qualname is not None:
            Settings.clone_attrs(qualname, settings, True)
            if DEPLOYMENT_ENV:
                Settings.clone_attrs(f'{qualname}.{DEPLOYMENT_ENV}', settings)
        return settings

    @staticmethod
    def clone_attrs(
        qualname: str,
        target: types.ModuleType,
        fatal: bool = False
    ):
        """Return a list of tuples containing all uppercased attributes of
        `module`, or those defined in the ``__all__`` member.
        """
        try:
            module = importlib.import_module(qualname)
            for k, v in inspect.getmembers(module):
                if (hasattr(module, '__all__') and k not in module.__all__)\
                or not str.isupper(k):
                    continue
                setattr(target, k, v)
        except ImportError:
            if fatal:
                raise ImproperlyConfigured(
                    "Can not import settings module %s" % qualname)


def __getattr__(attname: str):
    sys.modules[__name__].settings = Settings.import_settings(
        qualname=os.getenv('PYTHON_SETTINGS_MODULE')
    )
    return sys.module[__name__].settings
