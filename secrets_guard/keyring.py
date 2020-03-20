import logging
import os
import tempfile

from secrets_guard.conf import Conf
from secrets_guard.crypt import aes_key


# Basic implementation of a keyring.
#
# The goal is to not retype the password over and over again for multiple
# actions on the same store.
# This is achieved by saving an hash of the key into a file with the same name
# of the store in the system temporary folder (e.g. /tmp/password.skey).
# This guarantees that the keyring is freed-up on the next system boot.
# The content of the file is the actually the hashed key.

def keyring_put_key(store_name, store_key, is_plain_key=True):
    """
    Puts the given key (plain or already hashed) in the system temporary folder
    for further uses.
    :param store_name: the store name
    :param store_key: the store key
    :param is_plain_key: whether the key is plaintext or already hashed
    """
    keyring_path = os.path.join(tempfile.gettempdir(), store_name + Conf.KEYRING_EXTENSION)
    with open(keyring_path, "wb") as keyring:
        logging.info("Adding key to the keyring for store '%s'" % store_name)
        keyring.write(aes_key(store_key) if is_plain_key else store_key)


def keyring_has_key(store_name):
    """
    Returns whether the key for the given store exists in the keyring.
    :param store_name: the store name
    :return: whether the key exists
    """
    keyring_path = os.path.join(tempfile.gettempdir(), store_name + Conf.KEYRING_EXTENSION)
    return os.path.exists(keyring_path)


def keyring_get_key(store_name):
    """
    Returns the cached hash of the key for the store with the given name,
    or None if does not exist.
    :param store_name: the store name
    :return: the (hashed) store key
    """
    keyring_path = os.path.join(tempfile.gettempdir(), store_name + Conf.KEYRING_EXTENSION)
    if not keyring_has_key(store_name):
        return None

    with open(keyring_path, "rb") as keyring:
        logging.debug("Getting key from the keyring for store '%s'" % store_name)
        return keyring.read()


def keyring_del_key(store_name):
    """
    Deletes the key for the given store name from the keyring.
    :param store_name: the store name
    """
    keyring_path = os.path.join(tempfile.gettempdir(), store_name + Conf.KEYRING_EXTENSION)
    if os.path.exists(keyring_path):
        logging.info("Removing key from the keyring for store '%s'" % store_name)
        os.remove(keyring_path)

