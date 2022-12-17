import tempfile
from pathlib import Path

from secrets_guard.aes import aes_key

# Basic implementation of a keyring.
#
# The goal is to not retype the password over and over again for multiple
# actions on the same store.
# This is achieved by saving a hash of the key into a file with the same name
# of the store in the system temporary folder (e.g. /tmp/password.key).
# This guarantees that the keyring is freed-up on the next system boot.
# The content of the file is actually the hashed key.

def _keyring_path(store_name):
    return Path(tempfile.gettempdir()) / (store_name + ".key")

def keyring_put_key(store_name, store_key):
    """
    Puts the given key (plain or already hashed) in the keyring.
    """
    keyring_path = _keyring_path(store_name)
    with keyring_path.open("wb") as keyring:
        keyring.write(aes_key(store_key))

def keyring_has_key(store_name):
    """
    Returns whether the key for the given store exists in the keyring.
    """
    return _keyring_path(store_name).is_file()

def keyring_get_key(store_name):
    """
    Returns the key of the given name or None if it does not exist in the keyring.
    """
    if not keyring_has_key(store_name):
        return None

    with _keyring_path(store_name).open("rb") as keyring:
        return keyring.read()

def keyring_del_key(store_name):
    """
    Delete the key associaited with the given store name from the keyring.
    """
    keyring_path = _keyring_path(store_name)
    if keyring_path.is_file():
        keyring_path.unlink()
