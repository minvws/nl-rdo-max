import pytest

from ..test_utils import get_settings

@pytest.fixture
def disable_overflow(redis_mock):
    redis_mock.set(get_settings().overflow_idp_key, 'false')

