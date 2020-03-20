import os
from setuptools import setup, find_packages

from secrets_guard.conf import Conf


def read(file_name):
    with open(os.path.join(os.path.dirname(__file__), file_name)) as f:
        return f.read()


setup(
    name=Conf.APP_NAME,
    version=Conf.APP_VERSION,

    # Requires python3.5
    python_requires=">=3",

    # Automatically import packages
    packages=find_packages(),

    include_package_data=True,

    # Scripts to install to the user executable path.
    # Note that this might be something like /home/user/.local/bin
    # which in Debian distributions is not included in $PATH.
    # If you want to use just "compress" or "uncompress", you should add that
    # path to your $PATH.
    entry_points={
      'console_scripts': [
          'secrets=secrets_guard.main:main'
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
    long_description_content_type="text/x-rst",
    long_description=read('README.rst'),
    license="MIT",
    keywords="pass password private key encrypt decrypt crypt",
    url="https://github.com/Docheinstein/secrets-guard",
)
