from setuptools import setup, find_packages

setup(
    name="inge6",
    packages=find_packages(),
    package_dir={"inge6": "inge6"},
    package_data={
        "inge6": ["templates/saml/xml/*.jinja", "templates/saml/html/*.html"]
    },
)
