import logging
import os
from pathlib import Path


class Conf:
    LOGGING_LEVEL = logging.DEBUG
    STORE_EXTENSION = ".sec"
    BACKUP_EXTENSION = ".bck"
    DEFAULT_PATH = os.path.join(str(Path.home()), ".secrets")



