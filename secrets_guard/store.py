import json
import logging
import os
from shutil import copyfile

from secrets_guard.conf import Conf
from secrets_guard.crypt import aes_encrypt_file, aes_decrypt_file
from secrets_guard.utils import tabulate_enum, abort


# A store is actually a dictionary (and thus serialized as encrypted json)
# containing "fields" and data".
# Each element of "data" is called 'secret'.

# e.g.
# {
#   "fields": ["Field1", "Field2", ...]
#   "data": [
#       {"Field1": "MyVal", "Field2": "AnotherVal"},
#       {"Field1": "MyVal", "Field2": "AnotherVal"},
#       {"Field1": "MyVal", "Field2": "AnotherVal"},
#       ...
#   ]
# }

def store_backup(store_path, store_name):
    """
    Creates a copy of a store file in the same directory.
    :param store_path: the folder of the store
    :param store_name: the store name
    :return: the path of the backup
    """
    store_full_path = os.path.join(store_path, store_name)
    logging.info("Backing up store: %s", store_full_path)

    if not os.path.exists(store_path):
        logging.error("Path does not exist")
        return False

    backup_path = store_full_path + Conf.BACKUP_EXTENSION
    logging.debug("Creating store backup at %s", backup_path)

    copyfile(store_full_path, backup_path)

    return backup_path


def store_create(store_path, store_name, store_key, *store_fields):
    """
    Creates a store file.
    :param store_path: the folder of the store
    :param store_name: the store name
    :param store_key: the key to use for protect the store
    :param store_fields: the store fields as a list of strings
    :return: whether the store has been created successfully
    """
    logging.info("Creating store '%s' at path '%s' with fields %s",
                 store_name, store_path, store_fields)

    if not os.path.exists(store_path):
        logging.debug("Creating path %s since it does not exists", store_path)
        try:
            os.makedirs(store_path)
        except OSError:
            logging.warning("Exception occurred, cannot create directory")
            return False

    store_full_path = os.path.join(store_path, store_name)

    logging.debug("Store file path: %s", store_full_path)

    store_content = {"fields": store_fields, "data": []}
    store_json = json.dumps(store_content)
    logging.debug("Store file content is: %s", store_content)

    return aes_encrypt_file(store_full_path, store_key, store_json)


def store_destroy(store_path, store_name):
    """
    Destroys a store file.
    :param store_path: the folder of the store
    :param store_name: the store name
    :return: whjether the store has been destroyed successfully.
    """
    logging.info("Destroying store '%s' at path '%s'",
                 store_name, store_path)

    store_full_path = os.path.join(store_path, store_name)

    if not os.path.exists(store_full_path):
        logging.warning("Nothing to destroy, store does not exists")
        return False

    os.remove(store_full_path)
    return True


def store_open(store_path, store_name, store_key, abort_on_fail=True):
    """
    Opens a store and returns the store model.
    :param store_path: the folder of the store
    :param store_name: the store name
    :param store_key: the key to use for unlock the store
    :param abort_on_fail: whether abort if the store cannot be opened
    :return: the store dictionary, containing "fields" and "data"
    """

    def do_store_open():
        store_full_path = os.path.join(store_path, store_name)
        logging.info("Opening store file at: %s", store_full_path)

        if not os.path.exists(store_path):
            logging.error("Path does not exist")
            return None

        store_content = aes_decrypt_file(store_full_path, store_key)

        if not store_content:
            return None

        logging.debug("Store opened; content is: \n%s", store_content)
        try:
            store_json = json.loads(store_content)
            logging.debug("Store parsed content is: %s", store_json)
            if "data" not in store_json or "fields" not in store_json:
                logging.error("Invalid store content")
                return None
        except ValueError:
            logging.error("Invalid store content")
            return None

        return store_json

    store = do_store_open()

    if abort_on_fail and not store:
        abort("Error: unable to open store '%s'" % store_name)

    return store


def store_write(store_path, store_name, store_key, store):
    """
    Writes a new store content to a store file.
    :param store_path: the folder of the store
    :param store_name: the store name
    :param store_key: the key to use for protect the store
    :param store: the store model
    :return: whether the store has been written successfully
    """
    store_full_path = os.path.join(store_path, store_name)
    logging.info("Writing store file at: %s", store_full_path)

    if not os.path.exists(store_path):
        logging.error("Path does not exist")
        return False

    logging.debug("Actually flushing store %s content: %s", store_full_path, store)
    write_ok = aes_encrypt_file(store_full_path, store_key, json.dumps(store))

    return write_ok and os.path.exists(store_full_path)


def store_manage_write(store_path, store_name, store_key, store_action):
    """
    Attempts to execute store_action on the store and then write to the store
    file; if something goes wrong, keeps the store backup.
    :param store_path: the folder of the store
    :param store_name: the store name
    :param store_key: the key to use for protect the store
    :param store_action: the action to perform over the store
    :return: whether the store has been written successfully
    """
    store = store_open(store_path, store_name, store_key)

    if not store:
        logging.error("Error occurred while opening store")
        return False

    backup_path = store_backup(store_path, store_name)

    action_ok = store_action(store)

    if action_ok:
        logging.debug("Store action performed successfully, writing")
        write_ok = store_write(store_path, store_name, store_key, store)

        if write_ok:
            logging.debug("Store write ok, removing backup file at %s", backup_path)
            os.remove(backup_path)
            return True
        else:
            logging.warning("Store write failed; keeping backup")
    else:
        os.remove(backup_path)

    return False


def store_manage_read(store_path, store_name, store_key, store_action):
    """
    Opens the store and performs the store_action over the store.
    :param store_path: the folder of the store
    :param store_name: the store name
    :param store_key: the key to use for unlock the store
    :param store_action: the action to perform over the store
    :return: the outcome of the store action
    """
    store = store_open(store_path, store_name, store_key)

    if not store:
        logging.error("Error occurred while opening store")
        return False

    return store_action(store)


def store_show(store_path, store_name, store_key):
    """
    Prints the data of the show as tabulated data.
    :param store_path: the folder of the store
    :param store_name: the store name
    :param store_key: the key to use for unlock the store
    :return: whether the store has been printed successfully
    """
    s = store_open(store_path, store_name, store_key)

    if not s:
        logging.error("Cannot open store")
        return False

    print(tabulate_enum(s["fields"], s["data"]))
    # logging.info("\n" + tabulate_enum(s["fields"], s["data"]))
    return True
