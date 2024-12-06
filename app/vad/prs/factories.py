from app.vad.config.schemas import PrsConfig, PrsRepositoryType
from .repositories import ApiPrsRepository, MockPrsRepository, PrsRepository


class PrsRepositoryFactory:
    def __init__(self, prs_config: PrsConfig) -> None:
        self.config: PrsConfig = prs_config

    def create(self) -> PrsRepository:
        match self.config.prs_repository:
            case PrsRepositoryType.MOCK:
                return MockPrsRepository()

            case PrsRepositoryType.API:
                repository: ApiPrsRepository = ApiPrsRepository(
                    repo_base_url=self.config.repo_base_url,
                    organisation_id=self.config.organisation_id,
                )
                return repository

            case _:
                raise NotImplementedError("PRS client adapter not implemented yet.")
