import configparser
import logging

from inject import Binder

from .vad.repositories import KeyRepository

from .brp.repositories import ApiBrpRepository, BrpRepository, MockBrpRepository
from .config.schemas import Config, JweFactoryType
from .config.services import ConfigParser
from .prs.factories import PrsRepositoryFactory
from .prs.repositories import PrsRepository
from .utils import root_path
from .vad.service import JoseJweFactory, JweFactory, NoOpJweFactory
from .version.models import VersionInfo
from .version.services import read_version_info


def configure_bindings(binder: Binder, config_file: str) -> None:
    """
    Configure dependency bindings for the application.
    """
    config: Config = __parse_app_config(config_file=config_file)
    binder.bind(Config, config)
    # binder.bind(VersionInfo, read_version_info())

    setup_logging(binder=binder, config=config)

    __bind_prs_repository(binder, config)
    __bind_brp_repository(binder, config)
    __bind_jwe_factory(binder, config)
    __bind_key_repository(binder, config)


def setup_logging(binder: Binder, config: Config) -> None:
    logging.basicConfig(level=config.app.loglevel.upper())
    logger: logging.Logger = logging.getLogger(name=config.app.name)
    binder.bind(logging.Logger, logger)


def __parse_app_config(config_file: str) -> Config:
    config_parser = ConfigParser(
        config_parser=configparser.ConfigParser(
            interpolation=configparser.ExtendedInterpolation(),
        ),
        config_path=root_path(config_file),
    )
    return config_parser.parse()


def __bind_prs_repository(binder: Binder, config: Config) -> None:
    binder.bind_to_constructor(PrsRepository, PrsRepositoryFactory(config.prs).create)


def __bind_brp_repository(binder: Binder, config: Config) -> None:
    if config.brp.mock_brp:
        binder.bind(BrpRepository, MockBrpRepository())
    else:
        binder.bind_to_constructor(
            BrpRepository, lambda: ApiBrpRepository(config.brp.base_url, api_key=config.brp.api_key)
        )


def __bind_jwe_factory(binder: Binder, config: Config) -> None:
    match config.app.jwe_factory:
        case JweFactoryType.JOSE:
            binder.bind_to_constructor(JweFactory, lambda: JoseJweFactory())
        case JweFactoryType.NOOP:
            binder.bind_to_constructor(JweFactory, lambda: NoOpJweFactory())

        case _:
            raise ValueError(f"Unsupported JWE factory: {config.app.jwe_factory}")


def __bind_key_repository(binder: Binder, config: Config) -> None:
    binder.bind(KeyRepository, KeyRepository(config.app.jwe_encryption_key))
