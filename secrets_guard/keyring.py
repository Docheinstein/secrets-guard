import logging
import tempfile
from pathlib import Path

from secrets_guard import KEYRING_EXTENSION
from secrets_guard.crypt import aes_key


# Basic implementation of a keyring.
#
# The goal is to not retype the password over and over again for multiple
# actions on the same store.
# This is achieved by saving an hash of the key into a file with the same name
# of the store in the system temporary folder (e.g. /tmp/password.skey).
# This guarantees that the keyring is freed-up on the next system boot.
# The content of the file is the actually the hashed key.

def _keyring_path(store_name):
    return Path(tempfile.gettempdir()) / (store_name + KEYRING_EXTENSION)


def keyring_put_key(store_name, store_key):
    """
    Puts the given key (plain or already hashed) in the system temporary folder
    for further uses.
    :param store_name: the store name
    :param store_key: the store key
    """
    keyring_path = _keyring_path(store_name)
    with keyring_path.open("wb") as keyring:
        logging.info(f"Adding key to the keyring for store '{store_name}'")
        keyring.write(aes_key(store_key))


def keyring_has_key(store_name):
    """
    Returns whether the key for the given store exists in the keyring.
    :param store_name: the store name
    :return: whether the key exists
    """
    found = _keyring_path(store_name).is_file()
    logging.debug(f"Keyring found for {store_name} = {found}")
    return found

def keyring_get_key(store_name):
    """
    Returns the cached hash of the key for the store with the given name,
    or None if does not exist.
    :param store_name: the store name
    :return: the (hashed) store key
    """
    if not keyring_has_key(store_name):
        return None

    with _keyring_path(store_name).open("rb") as keyring:
        logging.debug(f"Getting key from the keyring for store {store_name}")
        return keyring.read()


def keyring_del_key(store_name):
    """
    Deletes the key for the given store name from the keyring.
    :param store_name: the store name
    """
    keyring_path = _keyring_path(store_name)
    if keyring_path.is_file():
        logging.info(f"Removing key from the keyring for store '{store_name}")
        keyring_path.unlink()

