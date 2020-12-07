import copy
import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path

from secrets_guard import STORE_EXTENSION
from secrets_guard.crypt import aes_encrypt_file, aes_decrypt_file
from secrets_guard.utils import tabulate_enum, abort, highlight, enumerate_data

# A store is actually a file, encrypted with AES,
# which content is the following json model.
# Each element of "data" is called 'secret'.
# e.g.
# {
#   "model": [
#       {
#        "name": "Field1",
#        "hidden": true | false,
#        "mandatory: true | false
#       },
#       ...
#   ],
#   "data": [
#       {"Field1": "MyVal", "Field2": "AnotherVal"},
#       {"Field1": "MyVal", "Field2": "AnotherVal"},
#       {"Field1": "MyVal", "Field2": "AnotherVal"},
#       ...
#   ]
# }


# Each field of the model of the store is called StoreField
# e.g. Name or Account or Password)
class StoreField:

    ADD_DATETIME = "Added"
    LAST_MODIFY_DATETIME = "Modified"

    class Json:
        NAME = "name"
        HIDDEN = "hidden"
        MANDATORY = "mandatory"

    def __init__(self, name, hidden=False, mandatory=False):
        self.name = name
        self.hidden = True if hidden else False
        self.mandatory = True if mandatory else False

    def __str__(self):
        return self.name + (" (hidden)" if self.hidden else "")

    def to_model(self):
        return {
            StoreField.Json.NAME: self.name,
            StoreField.Json.HIDDEN: self.hidden,
            StoreField.Json.MANDATORY: self.mandatory
        }

    @staticmethod
    def from_model(storefield_json):
        name = storefield_json.get(StoreField.Json.NAME, "")
        hidden = storefield_json.get(StoreField.Json.HIDDEN, None)
        mandatory = storefield_json.get(StoreField.Json.MANDATORY, None)
        sf = StoreField(name, hidden=hidden, mandatory=mandatory)
        return sf


class Store:

    class Json:
        MODEL = "model"
        DATA = "data"

    def __init__(self, stores_path, store_name, key=None):
        self._path = Path(stores_path, store_name + STORE_EXTENSION)
        self._plain_key = key if isinstance(key, str) else None
        self._hashed_key = key if isinstance(key, bytes) else None

        self._fields = []
        self._secrets = []
        
        logging.debug(f"Store initialized for path: {self._path}")
        logging.debug(f"Key type: {'plain' if self._plain_key else ('hashed' if self._hashed_key else 'none')}")

    @property
    def name(self):
        return self._path.stem

    @property
    def path(self):
        return self._path

    @property
    def key(self):
        return self._plain_key or self._hashed_key

    @property
    def fields(self):
        """
        Returns the store fields.
        :return: the store fields
        """
        return self._fields

    def fieldsnames(self, when=False):
        """
        Returns the store fields names.
        :param when: add the temporal fields (creation/modification)
        :return: the store fields names
        """

        ret = [f.name for f in self.fields]
        if when:
            ret += [StoreField.ADD_DATETIME, StoreField.LAST_MODIFY_DATETIME]
        return ret

    def add_fields(self, *fields):
        """
        Adds fields to the store (as StoreField).
        :param fields: the fields to add
        """

        self._fields += fields
        return True

    @property
    def secrets(self):
        """
        Returns the store data.
        :return: the store data
        """

        return self._secrets

    def secret(self, index):
        """
        Returns the secret at the given index.
        Note that  is is not the same as .secrets[index] since the secrets
        returned by secrets() are unordered.
        :param index: the secret index
        :return: the secret with the given index or None if it does not exist
        """
        ss = Store.sorted_secrets(self._secrets)
        if index < len(ss):
            return ss[index]
        return None

    def add_secrets(self, *secrets):
        """
        Adds secrets to the store.
        :param secrets: the secrets to add
        """

        for secret in secrets:
            safe_secret = {}
            self._apply_secret_change(safe_secret, secret,
                                      temporal_field=StoreField.ADD_DATETIME)
            logging.info(f"Adding secret: {safe_secret}")
            self._secrets.append(safe_secret)

        return True

    def remove_secrets(self, *secrets_ids):
        """
        Removes the secrets with the given id from the secrets.
        :param secrets_ids: the id of the secrets to remove
        :return whether the secret has been removed
        """

        logging.debug(f"Attempting secrets removal {secrets_ids}")

        # Sort now since we must ensure that the user provided ID
        # matches the index of the secrets.
        self._secrets = Store.sorted_secrets(self._secrets)

        at_least_one_removed = False

        for secret_id in sorted(secrets_ids, reverse=True):

            logging.debug(f"Attempting to remove {secret_id}")

            if secret_id >= len(self._secrets):
                logging.warning("Invalid secret id; out of bound")
                continue

            logging.info(f"Removing secret: {self._secrets[secret_id]}")

            del self._secrets[secret_id]
            at_least_one_removed = True

        return at_least_one_removed

    def clear_secrets(self):
        """
        Removes all  the store's secrets.
        """
        self._secrets = []

    def modify_secret(self, secret_id, secret_mod):
        """
        Modifies the secret with the given id using the given mod.
        :param secret_id: the secret it
        :param secret_mod: the new secret values
        :return whether the secret has been modified
        """

        if not secret_id < len(self._secrets):
            logging.error("Invalid secret id; out of bound")
            return False

        # Sort now since we must ensure that the user provided ID
        # matches the index of the secrets.
        self._secrets = Store.sorted_secrets(self._secrets)

        secret = self._secrets[secret_id]
        self._apply_secret_change(secret, secret_mod,
                                  temporal_field=StoreField.LAST_MODIFY_DATETIME)

        return True

    def clone_content(self, store):
        """
        Clones the content (only the model and the data)
        of another store into this store.
        :param store: the store to copy
        """
        self._fields = store.fields
        self._secrets = store.secrets

    def destroy(self):
        """
        Destroys the store file associated with this store and free this store.
        :return: whether the store has been destroyed successfully.
        """
        logging.info(f"Destroying store at path '{self._path}'")

        if not self._path.exists():
            logging.warning("Nothing to destroy, store does not exists")
            return False

        self._path.unlink()

        self._fields = []
        self._secrets = []

        return True

    def open(self, abort_on_fail=True):
        """
        Opens a store and parses the content into this store.
        :param abort_on_fail: whether abort if the store cannot be opened
        :return the store content
        """

        def do_store_open():
            logging.info(f"Opening store file at: {self._path}")
            if not self._path.exists():
                logging.error("Path does not exist")
                return None

            store_content = aes_decrypt_file(self._path, self.key)

            if not store_content:
                return None

            logging.debug(f"Store opened; content is: \n{store_content}")
            try:
                store_json = json.loads(store_content)
                logging.debug(f"Store parsed content is: {store_json}")
                if not Store.is_valid_store_json(store_json):
                    logging.error("Invalid store content")
                    return None
            except ValueError:
                logging.error("Invalid store content")
                return None

            return store_json

        jstore = do_store_open()

        if abort_on_fail and not jstore:
            abort(f"Error: unable to open store '{self.name}'")

        # Parse the content
        self._parse_model(jstore)

        return jstore is not None

    def save(self):
        """
        Writes the current store content to the store file.
        :return: whether the store has been written successfully
        """

        logging.info(f"Writing store file at: {self._path}")

        if not self._path.exists():
            logging.debug(f"Creating store at {self._path} since it does not exists")
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                logging.warning(f"Exception occurred, cannot create directory: {e}")
                return False

        logging.debug(f"Actually flushing store: {self._path}\n"
                      f"Model: {self.fieldsnames()} \n"
                      f"Secrets: {self._secrets}")

        write_ok = aes_encrypt_file(self._path, self.key,
                                    json.dumps(self.to_model()))

        return write_ok and self._path.exists()

    def show(self, table=True, when=False):
        """
        Prints the data of the store as tabulated data.
        :param table: whether show the data within a table
        :param when: whether show the creation/modification info
        :return: whether the store has been printed successfully
        """
        logging.debug("Showing store content...")

        if table:
            print(tabulate_enum(self.fieldsnames(when),
                                Store.sorted_secrets(self._secrets)))
        else:
            print(Store.list_secrets(self.fieldsnames(when),
                                     Store.sorted_secrets(self._secrets)))

        return True

    def grep(self, grep_pattern, colors=True, table=True, when=False):
        """
        Performs a regular expression between each field of each secret and
        prints the matches a tabular data.
        :param grep_pattern: the search pattern as a valid regular expression
        :param colors: whether highlight the matches
        :param table: whether show the data within a table
        :param when: whether show the creation/modification info
        :return: whether the secret has been grep-ed successfully
        """

        matches = []
        for i, secret in enumerate(Store.sorted_secrets(self._secrets)):
            secretmatch = None
            for field in secret:
                # logging.debug("Comparing %s against %s", field, grep_pattern)

                re_matches = re.finditer(grep_pattern, secret[field], re.IGNORECASE)

                for re_match in re_matches:
                    startpos, endpos = re_match.span()
                    logging.debug(f"Found re match in: {secret[field]}")

                    if colors:
                        # Do a copy, leave 'secret' as it is
                        if not secretmatch:
                            secretmatch = copy.copy(secret)

                        # Highlight
                        secretmatch[field] = highlight(secret[field], startpos, endpos)
                    else:
                        secretmatch = secret

            if secretmatch:
                secretmatch["ID"] = i
                matches.append(secretmatch)

        logging.debug(f"There are {len(matches)} matches")

        if table:
            print(tabulate_enum(self.fieldsnames(when), matches))
        else:
            print(Store.list_secrets(self.fieldsnames(when), matches))

        return True

    def _apply_secret_change(self, secret, secret_mod, temporal_field=None):
        """
        For each known field of store_fields push the value from secret_mod
        to secret.
        :param secret: the secret
        :param secret_mod: the secret modification (may contain only some fields)
        :param temporal_field: optionally set the field "temporal_field" equals
                               to the current datetime (i.e. for add/modify tracking)
        """
        store_fields = self.fieldsnames()

        logging.debug("Applying secret mod.\n"
                      f"Old: {secret}\n"
                      f"New: {secret_mod}")

        for store_field in store_fields:
            for mod_field in secret_mod:
                if store_field.lower() == mod_field.lower():
                    secret[store_field] = secret_mod[mod_field]

        if temporal_field:
            # Update the temporal field
            secret[temporal_field] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")

        logging.debug(f"Secret after mod: {secret}")

    def _parse_model(self, store_model):
        """
        Parse the json content and fill the fields and secrets of this store
        accordingly.
        :param store_model: the dictionary of the store as json
        """

        logging.debug(f"Parsing store model {store_model}")

        if not Store.is_valid_store_json(store_model):
            logging.warning("Invalid store json")
            return

        self._fields = [StoreField.from_model(field) for field in store_model[Store.Json.MODEL]]
        self._secrets = store_model[Store.Json.DATA]

    def to_model(self):
        """
        Returns a json dictionary representing this store.
        :return: this store as a json dictionary
        """
        return {
            Store.Json.MODEL: [f.to_model() for f in self.fields],
            Store.Json.DATA: self._secrets
        }

    def __str__(self):
        return f"""\
Store path: {self._path}
Fields: {self.fields}
Secrets: {self._secrets}\
"""

    @staticmethod
    def sorted_secrets(secrets):
        """
        Returns the secrets sorted by fields (in the order of the fields).
        :return: the store data sorted
        """

        def lowered(tup):
            return [str(f).lower() for f in tup]

        return sorted(secrets, key=lambda s: [lowered(t) for t in list(s.items())])

    @staticmethod
    def is_valid_store_json(j):
        """
        Returns whether the given json is a valid json for a store.
        :param j: the json to check
        :return: whether the json could be the json of a store
        """
        return j and Store.Json.MODEL in j and Store.Json.DATA in j

    @staticmethod
    def list_secrets(headers, secrets):
        """
        Returns a the content of the secrets, field per field.
        :param headers: the store headers
        :param secrets: the secrets
        :return: a string representing the secrets and their content
        """
        s = ""
        enum_headers, enum_data = enumerate_data(headers, secrets)

        for di, d in enumerate(enum_data):
            is_last_data = di >= len(enum_data) - 1

            for hi, h in enumerate(enum_headers):
                is_last_header = hi >= len(enum_headers) - 1

                if h not in d:
                    continue
                s += h + ": " + str(d[h])
                if not is_last_data or not is_last_header:
                    s += "\n"

            if not is_last_data:
                s += "-" * 20 + "\n"

        return s
