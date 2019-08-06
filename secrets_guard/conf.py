import os
from pathlib import Path


class LoggingLevels:
    CRITICAL = 50
    ERROR = 40
    WARNING = 30
    INFO = 20
    DEBUG = 10
    TRACE = 5


class Conf:
    LOGGING_LEVEL = LoggingLevels.WARNING
    STORE_EXTENSION = ".sec"
    KEYRING_EXTENSION = ".skey"
    DEFAULT_PATH = os.path.join(str(Path.home()), ".secrets")



