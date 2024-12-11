from setuptools import setup, find_packages

__version__ = "1.3.6"

requirements = [
    "fastapi",
    "dependency-injector>=4.0,<5.0",
    "pyop",
    "jwcrypto",
    "redis",
    "jinja2",
    "xmlsec",
    "lxml",
    "pyOpenSSL",
    "python3-saml==1.16.0",
    "python-multipart",
    "pynacl",
    "async-timeout",
    "inject==4.3.1",
]

setup(
    name="app",
    version=__version__,
    packages=find_packages(),
    package_dir={"app": "app"},
    package_data={"app": ["templates/saml/xml/*.jinja", "templates/saml/html/*.html"]},
    install_requires=requirements,
    extras_require={
        "dev": [
            "black",
            "uvicorn",
            "pylint",
            "bandit",
            "mypy",
            "autoflake",
            "coverage",
            "coverage-badge",
            "freezegun",
            "pytest",
            "pytest-mock",
            "pytest-docker",
            "pytest_redis",
            "pytest-asyncio",
            "freezegun",
            "types-redis",
            "types-python-dateutil",
            "types-requests",
            "httpx", 
            "faker"
        ]
    },
)
