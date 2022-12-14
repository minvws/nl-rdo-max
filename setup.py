# Copyright (c) 2020-2021 De Staat der Nederlanden, Ministerie van Volksgezondheid, Welzijn en Sport.
#
# Licensed under the EUROPEAN UNION PUBLIC LICENCE v. 1.2
#
# SPDX-License-Identifier: EUPL-1.2
#
from setuptools import setup, find_packages

__version__ = "1.3.6"

requirements = [
    # fastapi,
    'fastapi',
    'redis',
    'redis-collections',
    'pyop',
    'pycryptodome',
    'jwcrypto',
    'pyOpenSSL',
    'pyjwt',
    'jinja2',
    'lxml>=4.6.5',
    'xmlsec>=1.3.12',
    'pynacl',
    'python-multipart',
    'python-dateutil',

    # fastapi optional dependencies
    'itsdangerous',

    # Communication with services
    'python3-saml==1.14.0',
    'zeep==4.1.0',
    'unidecode==1.3.4',
    'requests==2.28.1',
]

setup(
    name="inge6",
    version=__version__,
    packages=find_packages(),
    package_dir={"inge6": "inge6"},
    package_data={
        "inge6": ["templates/saml/xml/*.jinja", "templates/saml/html/*.html"]
    },
    install_requires=requirements,
    extras_require={
        'dev': [
            'black',
            'uvicorn',
            'pylint',
            'bandit',
            'mypy',
            'autoflake',
            'coverage',
            'coverage-badge',
            'freezegun',
            'pytest',
            'pytest-asyncio',
            'pytest-cov',
            'pytest-mock',
            'pytest_redis',
            'pytest-docker',
            'requests-mock',
            'types-redis',
            'types-requests',
            'types-python-dateutil',
        ]
    }
)
