import copy
import json
import logging
import os
import re
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

    def __init__(self, path, name, key=None):
        self._path = path
        self._name = name

        self._key = key

        self._fullpath = os.path.join(path, name)
        self._fields = []
        self._secrets = []

    @property
    def name(self):
        return self._name

    @property
    def path(self):
        return self._key

    @property
    def key(self):
        return self._key

    def has_plain_key(self):
        """
        Returns whether the key in use is plaintext or already hashed.
        :return: whether the used key store is plaintext
        """
        return isinstance(self._key, str)

    @property
    def fullpath(self):
        return self._fullpath

    @property
    def fields(self):
        """
        Returns the store fields.
        :return: the store fields
        """
        return self._fields

    def fieldsnames(self):
        """
        Returns the store fields names.
        :return: the store fields names
        """

        names = []
        for f in self.fields:
            name = f.name
            # if f.hidden:
            #     name = "# " + name + " #"
            names.append(name)

        return names

    def add_fields(self, *fields):
        """
        Adds fields to the store (as StoreField).
        :param fields: the fields to add
        """

        for f in fields:
            self.fields.append(f)

        return True

    @property
    def secrets(self):
        """
        Returns the store data.
        :return: the store data
        """

        return self._secrets

    def add_secrets(self, *secrets):
        """
        Adds secrets to the store.
        :param secrets: the secrets to add
        """

        for secret in secrets:
            safe_secret = {}
            self._apply_secret_change(safe_secret, secret)
            logging.info("Adding secret: %s", safe_secret)
            self.secrets.append(safe_secret)

        return True

    def remove_secrets(self, *secrets_ids):
        """
        Removes the secrets with the given id from the secrets.
        :param secrets_ids: the id of the secrets to remove
        :return whether the secret has been removed
        """

        logging.debug("Attempting secrets removal %s", secrets_ids)

        at_least_one_removed = False

        for secret_id in sorted(secrets_ids, reverse=True):

            logging.debug("Attempting to remove %s", secret_id)

            if secret_id >= len(self.secrets):
                logging.warning("Invalid secret id; out of bound")
                continue

            logging.info("Removing secret: %s", self.secrets[secret_id])

            del self.secrets[secret_id]
            at_least_one_removed = True

        return at_least_one_removed

    def modify_secret(self, secret_id, secret_mod):
        """
        Modifies the secret with the given id using the given mod.
        :param secret_id: the secret it
        :param secret_mod: the new secret values
        :return whether the secret has been modified
        """

        if not secret_id < len(self.secrets):
            logging.error("Invalid secret id; out of bound")
            return False

        secret = self.secrets[secret_id]
        self._apply_secret_change(secret, secret_mod)

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
        logging.info("Destroying store at path '%s'", self._fullpath)

        if not os.path.exists(self._fullpath):
            logging.warning("Nothing to destroy, store does not exists")
            return False

        os.remove(self._fullpath)

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
            logging.info("Opening store file at: %s", self._fullpath)
            logging.debug("Using key '%s' ; plainkey? %s", self._key, self.has_plain_key())

            if not os.path.exists(self._fullpath):
                logging.error("Path does not exist")
                return None

            store_content = aes_decrypt_file(self._fullpath, self._key,
                                             is_plain_key=self.has_plain_key())

            if not store_content:
                return None

            logging.debug("Store opened; content is: \n%s", store_content)
            try:
                store_json = json.loads(store_content)
                logging.debug("Store parsed content is: %s", store_json)
                if not Store.is_valid_store_json(store_json):
                    logging.error("Invalid store content")
                    return None
            except ValueError:
                logging.error("Invalid store content")
                return None

            return store_json

        jstore = do_store_open()

        if abort_on_fail and not jstore:
            abort("Error: unable to open store '%s'" % self._name)

        # Parse the content
        self._parse_model(jstore)

        return jstore is not None

    def save(self):
        """
        Writes the current store content to the store file.
        :return: whether the store has been written successfully
        """

        logging.info("Writing store file at: %s", self._fullpath)

        if not os.path.exists(self._path):
            logging.debug("Creating path %s since it does not exists", self._path)
            try:
                os.makedirs(self._path)
            except OSError:
                logging.warning("Exception occurred, cannot create directory")
                return False

        logging.debug("Actually flushing store %s, \nModel: %s\nSecrets: %s",
                      self._fullpath, self.fields, self.secrets)

        write_ok = aes_encrypt_file(self._fullpath, self._key,
                                    json.dumps(self.to_model()),
                                    is_plain_key=self.has_plain_key())

        return write_ok and os.path.exists(self._fullpath)

    def show(self, table=True):
        """
        Prints the data of the store as tabulated data.
        :param table: whether show the data within a table
        :return: whether the store has been printed successfully
        """
        if table:
            print(tabulate_enum(self.fieldsnames(), Store.sorted_secrets(self.secrets)))
        else:
            print(Store.list_secrets(self.fieldsnames(), Store.sorted_secrets(self.secrets)))

        return True

    def grep(self, grep_pattern, colors=True, table=True):
        """
        Performs a regular expression between each field of each secret and
        prints the matches a tabular data.
        :param grep_pattern: the search pattern as a valid regular expression
        :param colors: whether highlight the matches
        :param table: whether show the data within a table
        :return: whether the secret has been grep-ed successfully
        """

        matches = []
        for secret in self.secrets:
            secretmatch = None
            for field in secret:
                # logging.debug("Comparing %s against %s", field, grep_pattern)

                re_matches = re.finditer(grep_pattern, secret[field], re.IGNORECASE)

                for re_match in re_matches:
                    startpos, endpos = re_match.span()
                    logging.debug("Found re match in: %s ", secret[field])

                    if colors:
                        # Do a copy, leave 'secret' as it is
                        if not secretmatch:
                            secretmatch = copy.copy(secret)

                        # Highlight
                        secretmatch[field] = highlight(secret[field], startpos, endpos)
                    else:
                        secretmatch = secret

            if secretmatch:
                matches.append(secretmatch)

        matches = Store.sorted_secrets(matches)
        for i, match in enumerate(matches):
            match["ID"] = i

        logging.debug("There are %d matches", len(matches))

        if table:
            print(tabulate_enum(self.fieldsnames(), Store.sorted_secrets(matches)))
        else:
            print(Store.list_secrets(self.fieldsnames(), Store.sorted_secrets(matches)))

        return True

    def _apply_secret_change(self, secret, secret_mod):
        """
        For each known field of store_fields push the value from secret_mod
        to secret.
        :param secret: the secret
        :param secret_mod: the secret modification (may contain only some fields)
        """
        store_fields = self.fieldsnames()

        for store_field in store_fields:
            for mod_field in secret_mod:
                if store_field.lower() == mod_field.lower():
                    secret[store_field] = secret_mod[mod_field]

    def _parse_model(self, store_model):
        """
        Parse the json content and fill the fields and secrets of this store
        accordingly.
        :param store_model: the dictionary of the store as json
        """

        logging.debug("Parsing store model %s", store_model)

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
            Store.Json.DATA: self.secrets
        }

    def __str__(self):
        s = "Store path: " + self._fullpath + "\n"

        s += "Fields: "

        for field in self.fields:
            s += field

        s += "\n"

        s += "Secrets: "

        for secret in self.secrets:
            s += secret

        return s

    @staticmethod
    def sorted_secrets(secrets):
        """
        Returns the secrets sorted by fields (in the order of the fields).
        :return: the store data sorted
        """

        return sorted(secrets, key=lambda s: list(s.items()))

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

        for d in enum_data:
            for h in enum_headers:
                if h not in d:
                    continue
                s += h + ": " + str(d[h]) + "\n"
            s += "-" * 20 + "\n"

        return s
