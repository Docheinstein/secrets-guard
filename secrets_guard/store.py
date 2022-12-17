import json
from datetime import datetime
from pathlib import Path

from secrets_guard.aes import aes_encrypt_file, aes_decrypt_file

FIELD_ADDED = "Added"
FIELD_MODIFIED = "Modified"


"""
STORE
{
#   "model": [
#       {
#        "name": "Field1",
#        "hidden": true | false,
#        "mandatory: true | false
#       },
#       ...
#   ],
#   "data": [
#       {"field1": "val1", "field2": "val2"},
#       {"field1": "val1", "field2": "val2"},
#       {"field1": "val1", "field2": "val2"},
#       ...
#   ]
}
"""

class Store:
    def __init__(self, path: Path, key: str | bytes = None):
        self.path = path
        self.key = key
        self.content = {
            "model": [],
            "data": []
        }

    def load(self):
        result = aes_decrypt_file(self.path, self.key)

        if not result:
            return False

        try:
            self.content = json.loads(result)
            return True
        except ValueError:
            return False

    def save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            pass


        write_ok = aes_encrypt_file(self.path, self.key,
                                    json.dumps(self.content))

        return write_ok and self.path.exists()

    def destroy(self):
        if not self.path.is_file():
            return False

        self.path.unlink()
        return True

    def get_fields(self):
        return self.content["model"]

    def add_field(self, name, hidden=False, mandatory=False):
        self.content["model"].append({
            "name": name,
            "hidden": hidden,
            "mandatory": mandatory
        })

    def get_secrets(self):
        secrets = self.content["data"]

        def lowered(tup):
            return [str(f).lower() for f in tup]

        return sorted(secrets, key=lambda s: [lowered(t) for t in list(s.items())])


    def get_secret_by_id(self, secret_id):
        secrets = self.get_secrets()

        if 0 <= secret_id < len(secrets):
            return secrets[secret_id]
        return None

    def clear_secrets(self):
        self.content["data"] = []

    def _modify_secret(self, secret, secret_mod, update_date_field=None):
        for f in self.get_fields():
            if f["name"] in secret_mod:
                secret[f["name"]] = secret_mod[f["name"]]

        if update_date_field:
            secret[update_date_field] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        return secret

    def add_secret(self, secret):
        new_secret = {}
        self._modify_secret(new_secret, secret, update_date_field=FIELD_ADDED)
        self.content["data"].append(new_secret)
        return True

    def modify_secret(self, secret_id, secret_mod):
        secret = self.get_secret_by_id(secret_id)

        if not secret:
            return False

        self._modify_secret(secret, secret_mod, update_date_field=FIELD_MODIFIED)
        return True


    def remove_secret(self, secret_id):
        secrets = self.get_secrets()

        if 0 <= secret_id < len(secrets):
            secret_ro_remove = secrets[secret_id]
            try:
                self.content["data"].remove(secret_ro_remove)
                return True
            except ValueError:
                return False
        return False
