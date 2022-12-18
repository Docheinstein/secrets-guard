import os
from setuptools import setup, find_packages

def read(file_name):
    with open(os.path.join(os.path.dirname(__file__), file_name)) as f:
        return f.read()


setup(
    name="secrets-guard",
    version="0.17",

    # Requires python3.5
    python_requires=">=3",

    # Automatically import packages
    packages=find_packages(),

    include_package_data=True,

    entry_points={
      'console_scripts': [
          'secrets=secrets_guard.__main__:main'
      ]
    },

    # Tests
    test_suite="tests",

    # Dependencies
    install_requires=['pycryptodomex', 'gitpython'],

    # Metadata
    author="Stefano Dottore",
    author_email="docheinstein@gmail.com",
    description="Encrypts and decrypts private information",
    long_description=read('README.md'),
    long_description_content_type="text/markdown",
    license="MIT",
    keywords="pass password private key encrypt decrypt crypt",
    url="https://github.com/Docheinstein/secrets-guard",
)
