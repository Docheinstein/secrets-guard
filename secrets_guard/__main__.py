import argparse
import datetime
import re
import sys
import json
from getpass import getpass
from pathlib import Path

from secrets_guard.git import git_pull, git_push
from secrets_guard.keyring import keyring_get_key, keyring_put_key
from secrets_guard.store import Store, FIELD_ADDED, FIELD_MODIFIED

SECRETS_PATH = Path.home() / ".secrets"
FIELD_ATTRIBUTE_HIDDEN = "h"
FIELD_ATTRIBUTE_MANDATORY = "m"

COLOR_RESET = "\33[0m"
COLOR_RED = "\33[31m"

def abort(*args, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
    exit(1)

def prompt(message, secure=False, double_check_message=None):
    while True:
        p1 = getpass(message) if secure else input(message)

        if not double_check_message:
            return p1

        p2 = getpass(double_check_message) if secure else input(double_check_message)

        if p1 == p2:
            return p1

def numerate(data, enum_field="ID"):
    for i, d in enumerate(data):
        d[enum_field] = i

def sort(data, sort_field, reverse):
    field_type = None

    for d in data:
        x = d.get(sort_field)
        if isinstance(x, int):
            field_type = int
            break
        if isinstance(x, str):
            field_type = str
            break

    def cmp(d):
        x = d.get(sort_field)
        if field_type == str:
            return x.lower() if x else ""
        if field_type == int:
            return x if x else 0
        return 0

    return sorted(data, key=cmp, reverse=reverse)

def tabulate(headers, data):
    ANSI_ESCAPE_REGEX = re.compile("\x1B\\[[0-9]+m")

    def escaped_text_length(text):
        # Remove '\33[??m' codes from text
        ansi_colors = ANSI_ESCAPE_REGEX.findall(text)
        ansi_colors_len = 0
        if ansi_colors and len(ansi_colors) > 0:
            ansi_colors_len = sum([len(c) for c in ansi_colors])
        return len(text) - ansi_colors_len

    HALF_PADDING = 1
    PADDING = 2 * HALF_PADDING

    out = ""

    max_lengths = {}

    # Compute max length for each field
    for h in headers:
        m = len(h)
        for d in data:
            if h in d:
                m = max(m, escaped_text_length(str(d[h])))
        max_lengths[h] = m

    def separator_row(first=False, last=False):
        s = "┌" if first else ("└" if last else "├")

        for hh_i, hh in enumerate(headers):
            s += ("─" * (max_lengths[hh] + PADDING))
            if hh_i < len(headers) - 1:
                 s += "┬" if first else ("┴" if last else "┼")

        s += "┐" if first else ("┘" if last else "┤")

        if not last:
            s += "\n"

        return s

    def data_cell(filler):
        return (" " * HALF_PADDING) + filler() + (" " * HALF_PADDING)

    def data_cell_filler(text, fixed_length):
        # Consider ANSI color before pad
        return text.ljust(fixed_length + (len(text) - escaped_text_length(text)))

    # Row
    out += separator_row(first=True)

    # Headers
    for h in headers:
        out += "│" + data_cell(lambda: data_cell_filler(h, max_lengths[h]))
    out += "│\n"

    # Row
    out += separator_row()

    # Data
    for d in data:
        for dh in headers:
            out += "│" + data_cell(
                lambda: data_cell_filler((str(d[dh]) if dh in d else " "), max_lengths[dh])
            )
        out += "│\n"

    # Row
    out += separator_row(last=True)

    return out

def highlight(text, spans, color=COLOR_RED):
    """
    Highlights the text by insert the given ANSi color (default: red).
    """

    def insert_into(source, insert, pos):
        return source[:pos] + insert + source[pos:]

    spans = sorted(spans, key=lambda s: s[0], reverse=True)

    highlighted_text = text
    for (startpos, endpos) in spans:
        highlighted_text = insert_into(highlighted_text, COLOR_RESET, endpos)
        highlighted_text = insert_into(highlighted_text, color, startpos)

    return highlighted_text

def get_stores_path(args, require_exist=True):
    p = Path(args["path"] or SECRETS_PATH)
    if require_exist and not p.exists():
        abort(f"ERROR: secrets path does not exist ({p})")
    return p


def get_or_prompt(args, key, message, secure=False, double_check_message=None):
    v = args.get(key)
    if v:
        return v

    return prompt(message, secure=secure, double_check_message=double_check_message)

def get_store_key(args, store_name):
    # check in arguments
    key = args["key"]
    if key:
        return key

    # check in keyring
    key = keyring_get_key(store_name)
    if key:
        return key

    # prompt
    key = get_or_prompt(args, "key", "Store key: ", secure=True)

    # save in keyring
    keyring_put_key(store_name, key)

    return key


def command_create(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    key = get_store_key(args, name)

    store_path = path / f"{name}.sec"

    raw_fields = args["fields"]
    if not raw_fields:
        raw_fields = []
        i = 1
        print("\n"
              "Insert store fields with format <name>[+[h][m]].\n"
              "+ m (mandatory)\n"
              "+ h (hidden)\n"
              "(Leave empty for terminate the fields insertion)\n")

        while True:
            f = input(f"{i} ° field: ")
            if not f:
                break

            raw_fields.append(f)
            i += 1

    store = Store(store_path, key)
    for raw_field in raw_fields:
        field_parts = raw_field.split("+")
        field_name = field_parts[0]
        field_modifiers = field_parts[1] if len(field_parts) > 1 else []

        store.add_field(field_name,
                        hidden=FIELD_ATTRIBUTE_HIDDEN in field_modifiers,
                        mandatory=FIELD_ATTRIBUTE_MANDATORY in field_modifiers)

    if not store.save():
        abort("ERROR: failed to save store")


def command_destroy(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    store_path = path / f"{name}.sec"

    store = Store(store_path)
    ok = store.destroy()
    if not ok:
        abort("ERROR: failed to destroy store")


def command_list(args):
    path = get_stores_path(args, require_exist=False)

    stores = sorted([
        store_path.stem
        for store_path in path.iterdir()
        if store_path.suffix == ".sec"
    ])

    if args["json"]:
        print(json.dumps(stores))
    else:
        for s in stores:
            print(s)

def _command_projection(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    key = get_store_key(args, name)
    store_path = path / f"{name}.sec"

    fields = args["fields"]

    store = Store(store_path, key)
    if not store.load():
        abort("ERROR: failed to load store")

    if not fields:
        fields = [f["name"] for f in store.get_fields()]
    if "ID" not in fields:
        fields = ["ID"] + fields
    if args["when"]:
        if FIELD_ADDED not in fields:
            fields += [FIELD_ADDED]
        if FIELD_MODIFIED not in fields:
            fields += [FIELD_MODIFIED]

    secrets = store.get_secrets()
    numerate(secrets, enum_field="ID")

    if args["sort"]:
        secrets = sort(secrets, args["sort"], reverse=args["reverse"])

    display_secrets = []
    for secret in secrets:
        display_secret = {}
        for f in fields:
            if f in secret:
                display_secret[f] = secret[f]
        display_secrets.append(display_secret)

    return fields, display_secrets

def command_show(args):
    fields, display_secrets = _command_projection(args)

    if args["json"]:
        print(json.dumps(display_secrets))
    else:
        print(tabulate(fields, display_secrets))

def command_grep(args):
    fields, projection_secrets = _command_projection(args)
    pattern = get_or_prompt(args, "pattern", "Search pattern: ")

    display_secrets = []
    for s in projection_secrets:
        match = False
        display_secret = {}
        for k, v in s.items():
            v_highlighted = str(v)
            re_matches = list(re.finditer(pattern, v_highlighted, re.IGNORECASE))
            if re_matches:
                match = True
                if not args["json"]:
                    matches = [re_match.span() for re_match in re_matches]
                    v_highlighted = highlight(v_highlighted, matches)

            display_secret[k] = v_highlighted
        if match:
            display_secrets.append(display_secret)

    if args["json"]:
        print(json.dumps(display_secrets))
    else:
        print(tabulate(fields, display_secrets))


def command_clear(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    key = get_store_key(args, name)
    store_path = path / f"{name}.sec"

    store = Store(store_path, key)
    if not store.load():
        abort("ERROR: failed to load store")

    store.clear_secrets()

    if not store.save():
        abort("ERROR: failed to save store")

def command_change_key(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    key = get_or_prompt(args, "key", "Old store key: ", secure=True)
    new_key = get_or_prompt(args, "new", "New store key: ", secure=True)
    store_path = path / f"{name}.sec"

    store = Store(store_path, key)
    if not store.load():
        abort("ERROR: failed to load store")

    store.key = new_key

    if not store.save():
        abort("ERROR: failed to save store")

def command_add(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    key = get_store_key(args, name)
    store_path = path / f"{name}.sec"
    data = args["data"] or []

    secret = {}
    for d in data:
        try:
            key, value = d.split("=", maxsplit=1)
            secret[key] = value
        except:
            pass

    store = Store(store_path, key)
    if not store.load():
        abort("ERROR: failed to load store")

    if not secret:
        # prompt all
        prompt_fields = store.get_fields()
    else:
        # prompt only mandatory
        prompt_fields = []
        for f in store.get_fields():
            if f["mandatory"] and f["name"] not in secret:
                prompt_fields.append(f)

    for f in prompt_fields:
        secret[f["name"]] = prompt(f'{f["name"]}: ', secure=f["hidden"])

    store.add_secret(secret)

    if not store.save():
        abort("ERROR: failed to save store")

def command_modify(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    key = get_store_key(args, name)
    secret_id = get_or_prompt(args, "key", "ID of the secret to modify: ")
    store_path = path / f"{name}.sec"
    data = args["data"] or []

    try:
        secret_id = int(secret_id)
    except ValueError:
        abort("ERROR: invalid secret format")

    secret_mod = {}
    for d in data:
        try:
            key, value = d.split("=", maxsplit=1)
            secret_mod[key] = value
        except:
            pass

    store = Store(store_path, key)
    if not store.load():
        abort("ERROR: failed to load store")

    if not secret_mod:
        secret = store.get_secret_by_id(secret_id)
        if not secret:
            abort(f"ERROR: secret with ID {secret_id} not found")

        fields = store.get_fields()

        while True:
            print("Select the field to modify:")
            for i, f in enumerate(fields):
                print(f"{i}. {f['name']} ({'*' * len(secret[f['name']]) if f['hidden'] else secret[f['name']]})")
            choice = input()
            try:
                choice = int(choice)
                if 0 <= choice < len(fields):
                    break
            except:
                pass

        chosen_field = fields[choice]
        secret_mod[chosen_field["name"]] = prompt(
            f"New value of \"{chosen_field['name']}\": ",
            secure=chosen_field["hidden"],
        )

    store.modify_secret(secret_id, secret_mod)

    if not store.save():
        abort("ERROR: failed to save store")


def command_remove(args):
    path = get_stores_path(args, require_exist=False)
    name = get_or_prompt(args, "name", "Store name: ")
    key = get_store_key(args, name)
    store_path = path / f"{name}.sec"

    secrets_to_remove = args["secrets"]

    store = Store(store_path, key)
    if not store.load():
        abort("ERROR: failed to load store")

    if not secrets_to_remove:
        x = prompt("ID of the secret(s) to remove: ")
        secrets_to_remove = x.split(" ")

    try:
        secrets_to_remove = [int(s) for s in secrets_to_remove]
    except ValueError:
        abort("ERROR: invalid secrets format")

    for s in sorted(secrets_to_remove, reverse=True):
        if not store.remove_secret(s):
            print(f"ERROR: failed to remove secret {s}")

    if not store.save():
        abort("ERROR: failed to save store")

def command_push(args):
    path = get_stores_path(args, require_exist=False)
    if not git_push(path, commit_message="Committed on " + datetime.datetime.now().strftime("%H:%M:%S %d/%m/%Y")):
        abort("ERROR: failed to push")

def command_pull(args):
    path = get_stores_path(args, require_exist=False)
    if not git_pull(path):
        abort("ERROR: failed to pull")


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt private data using AES"
    )

    subparsers = parser.add_subparsers(
        title="commands",
        required=True
    )


    # add
    add_parser = subparsers.add_parser(
        "add",
        description="add a secret to a store"
    )
    add_parser.set_defaults(func=command_add)

    add_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    add_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    add_parser.add_argument(
        "-d", "--data",
        dest="data",
        action="append",
        help="set data (must be in the form <key>=<value>)"
    )
    add_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )


    # change-key
    change_key_parser = subparsers.add_parser(
        "change-key",
        description="change the key of a store"
    )
    change_key_parser.set_defaults(func=command_change_key)
    change_key_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    change_key_parser.add_argument(
        "new_key",
        nargs="?",
        help="new store key (plaintext)"
    )
    change_key_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    change_key_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )


    # clear
    clear_parser = subparsers.add_parser(
        "clear",
        description="clear the content of a store"
    )
    clear_parser.set_defaults(func=command_clear)

    clear_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    clear_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    clear_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )

    # create
    create_parser = subparsers.add_parser(
        "create",
        description="create a new store"
    )
    create_parser.set_defaults(func=command_create)

    create_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    create_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    create_parser.add_argument(
        "-f", "--field",
        metavar="FIELD",
        dest="fields",
        action="append",
        help="declare a field (syntax is <name>[+[h][m]])"
    )
    create_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )

    # destroy
    destroy_parser = subparsers.add_parser(
        "destroy",
        description="destroy a store"
    )
    destroy_parser.set_defaults(func=command_destroy)

    destroy_parser.add_argument(
        "name",
        nargs="?",
        help="store key (plaintext)"
    )
    destroy_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )


    # grep
    grep_parser = subparsers.add_parser(
        "grep",
        description="filter the content of a store"
    )
    grep_parser.set_defaults(func=command_grep)
    grep_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    grep_parser.add_argument(
        "pattern",
        nargs="?",
        help="search pattern"
    )
    grep_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    grep_parser.add_argument(
        "-f", "--field",
        dest="fields",
        action="append",
        help="show only given fields"
    )
    grep_parser.add_argument(
        "-s", "--sort",
        dest="sort",
        help="sort secrets by field"
    )
    grep_parser.add_argument(
        "-r", "--reverse",
        action="store_const", const=True, default=False,
        help="reverse sort order"
    )
    grep_parser.add_argument(
        "-w", "--when",
        action="store_const", const=True, default=False,
        help="show add/last modify date"
    )
    grep_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )
    grep_parser.add_argument(
        "-j", "--json",
        action="store_const", const=True, default=False,
        dest="json",
        help="output as json"
    )

    # list
    list_parser = subparsers.add_parser(
        "list",
        description="list stores"
    )
    list_parser.set_defaults(func=command_list)
    list_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )
    list_parser.add_argument(
        "-j", "--json",
        action="store_const", const=True, default=False,
        dest="json",
        help="output as json"
    )


    # modify
    modify_parser = subparsers.add_parser(
        "modify",
        description="modify a secret in a store"
    )
    modify_parser.set_defaults(func=command_modify)

    modify_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    modify_parser.add_argument(
        "secret",
        nargs="?",
        help="id of secret to modify"
    )
    modify_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    modify_parser.add_argument(
        "-d", "--data",
        dest="data",
        action="append",
        help="set data (must be in the form <key>=<value>)"
    )
    modify_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )


    pull_parser = subparsers.add_parser(
        "pull",
        description="pull from remote git repository"
    )
    pull_parser.set_defaults(func=command_pull)
    pull_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )

    # push
    push_parser = subparsers.add_parser(
        "push",
        description="push to remote git repository"
    )
    push_parser.set_defaults(func=command_push)
    push_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )


    # remove
    remove_parser = subparsers.add_parser(
        "remove",
        description="remove a secret from a store"
    )
    remove_parser.set_defaults(func=command_remove)

    remove_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    remove_parser.add_argument(
        "secrets",
        nargs="*",
        help="id of secret(s) to remove"
    )
    remove_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    remove_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )

    # show
    show_parser = subparsers.add_parser(
        "show",
        description="show the content of a store"
    )
    show_parser.set_defaults(func=command_show)
    show_parser.add_argument(
        "name",
        nargs="?",
        help="store name"
    )
    show_parser.add_argument(
        "-k", "--key",
        help="store key (plaintext)"
    )
    show_parser.add_argument(
        "-f", "--field",
        dest="fields",
        action="append",
        help="show only given fields"
    )
    show_parser.add_argument(
        "-s", "--sort",
        dest="sort",
        help="sort secrets by field"
    )
    show_parser.add_argument(
        "-r", "--reverse",
        action="store_const", const=True, default=False,
        help="reverse sort order"
    )
    show_parser.add_argument(
        "-w", "--when",
        action="store_const", const=True, default=False,
        help="show add/last modify date"
    )
    show_parser.add_argument(
        "-p", "--path",
        dest="path",
        help="secrets path (default is ~/.secrets)"
    )
    show_parser.add_argument(
        "-j", "--json",
        action="store_const", const=True, default=False,
        dest="json",
        help="output as json"
    )

    args = parser.parse_args(sys.argv[1:])
    args.func(args=vars(args))

if __name__ == '__main__':
    main()
