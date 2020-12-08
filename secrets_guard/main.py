import argparse
import datetime
import logging
import sys
import traceback
from pathlib import Path
from typing import Union

from secrets_guard import gitsync, APP_NAME, APP_VERSION, DEFAULT_SECRETS_PATH, STORE_EXTENSION
from secrets_guard.cli import Options, Commands, SecretAttributes
from secrets_guard.keyring import keyring_get_key, keyring_put_key, keyring_has_key, keyring_del_key
from secrets_guard.store import Store, StoreField
from secrets_guard.utils import keyval_list_to_dict, abort, terminate, prompt

HELP = """\
NAME 
    secrets - encrypt and decrypt private information (such as passwords)

SYNOPSIS
    secrets <COMMAND> [COMMAND_OPTIONS] [GENERAL_OPTIONS]
    
DESCRIPTION
    Stores and retrieves encrypted data to/from files.
    
    Each command can be used either in batch or interactive mode;
    each mandatory but not specified argument will be required interactively.
    
    One of the following command must be specified:
    
GLOBAL COMMANDS         
    list [--path <PATH>]
        List the names of the stores found at the path specified
        by --path (or at the default one if not specified).
    
        e.g. secrets list
 
STORE COMMANDS
    create [<STORE_NAME>] [--fields FIELDS] [--path <PATH>] [--key <STORE_KEY>]
        Creates a new store at the given path using the given key.
        The FIELDS must be expressed as a comma separated list of field names.
        
        Furthermore some attributes can be expressed for the fields by appending
        "+<attr_1><attr_2>..." after the field name.
        
        The available attributes are
        1) h: hidden (the user input is not shown)
        2) m: mandatory (the field must contain a non empty string)
        
        e.g. secrets create password --fields Site,Account,Password,Other
        e.g. secrets create password --fields Site+m,Account+m,Password+mh,Other
        
    destroy [<STORE_NAME>] [--path <PATH>]
        Destroys the store at the given path.
        
        e.g. secrets destroy password

    key [<STORE_NAME>] [<NEW_STORE_KEY>] [--path <PATH>] [--key <STORE_KEY>]
        Changes the key of the store from STORE_KEY to NEW_STORE_KEY.
        
        e.g. secrets key newkey
        
    clear [<STORE_NAME>] [--path <PATH>] [--key <STORE_KEY>]
        Clears the content (all the secrets) of a store.
        The model is left unchanged.
        
    show [<STORE_NAME>] [--no-table] [--when] [--path <PATH>] [--key <STORE_KEY>]
        Decrypts and shows the content of an entire store.
        The --when parameter shows also temporal info (add/last modify date)

        e.g. secrets show password
            
    grep [<STORE_NAME>] [<SEARCH_PATTERN>] [--fields FIELDS] [--when]  [--no-color] [--no-table] [--path <PATH>] [--key <STORE_KEY>]
        Performs a regular expression search between the data of the store.
        The SEARCH_PATTERN can be any valid regular expression.
        The matches will be highlighted unless --no-color is specified.
        The --when parameter shows also temporal info (add/last modify date)
        If FIELDS is given, it must be expressed as a comma separated list of field names.

        e.g. secrets grep password MyPass
        e.g. secrets grep password "^My.*word" --fields Name,Other
        
SECRET COMMANDS
    add [<STORE_NAME>] [--data DATA] [--path <PATH>] [--key <STORE_KEY>]
        Inserts a new secret into a store.
        The DATA must be expressed as a key=value comma separated list where the 
        key should be a field of the store.
        
        e.g. secrets add password --data Site="Megavideo",Account="me@gmail.com",Password="MyPassword" 

    remove [<STORE_NAME>] [<SECRET_IDS>*] [--path <PATH>] [--key <STORE_KEY>]
        Removes the secret(s) with the given SECRET_IDS from the store.
        The SECRET_IDS should be a comma separated list of IDs retrieved 
        using the secrets grep or the show command.
        
        e.g. secrets remove password 12
        e.g. secrets remove password 12,14,15,7 11
    
    modify [<STORE_NAME>] [<SECRET_ID>] [--data DATA] [--path <PATH>] [--key <STORE_KEY>]
        Modifies the secret with the given SECRET_ID using the given DATA.
        The DATA must be expressed as a key=value list.
    
        e.g. secrets modify password 11 --data Password="MyNewPassword"
               
GIT COMMANDS
    push [--message <COMMIT_MESSAGE>] [--path <PATH>] 
        Commits and pushes to the remote git repository.
        Actually performs "git add ." , "git commit -m 'COMMIT_MESSAGE'" and
        "git push" on the given path.
        Note that the action is related to the whole repository, 
        not a particular store.

        If the COMMIT_MESSAGE is not specified, a default commit message 
        will be created.
        The credentials might be required by the the invoked git push routine.
        
        e.g. secrets push
        e.g. secrets push
        e.g. secrets push --message "Added Google password"
          
        Pull from the remote git branch.
        Note that the action is related to the whole repository, 
        not a particular store.

        e.g. secrets pull

GLOBAL OPTIONS
    --help
        Shows this help message.
        
    --version
        Shows the version number.

    --verbose
        Prints debug statements.
    
    --no-keyring
        Do not use the keyring for retrieve the password.
        By default a password used for open a store is cached in the keyring
        for further uses."""


def init_logging(lv):
    """ Initializes the logging. """
    logging.basicConfig(
        level=lv,
        format="[%(levelname)s] %(asctime)s %(message)s",
        datefmt='%d/%m/%y %H:%M:%S',
        stream=sys.stdout)

# =====================
# ===== ARGUMENTS =====
# =====================

#
# def parse_arguments(arguments):
#     """
#     Parses the argument list.
#     :param arguments: the arguments to parse (sys.argv)
#     :return: the parsed arguments
#     """
#     # logging.debug("Parsing arguments %s", arguments)
#
#     parsed_args = Args()
#
#     if len(arguments) < 1:
#         abort("Error: the command must be specified")
#
#     # Parse command
#
#     command_request = arguments[0]
#
#     for command in Commands.__dict__.values():
#         if command == command_request:
#             parsed_args.command = command
#
#     if parsed_args.command is None:
#         abort("Error: unknown command '%s'" % command_request)
#
#     # Parse position/keyword arguments
#
#     i = 1
#     current_args_stream = parsed_args.args
#
#     while i < len(arguments):
#         arg = arguments[i]
#         if not arg.startswith("--"):
#             # Parameter of the current argument
#             # logging.debug("Adding parameter %s to current argument", arg)
#             current_args_stream.append(arg)
#         else:
#             # New argument
#             # logging.debug("Found new argument: %s", arg)
#             current_args_stream = []
#             parsed_args.kwargs[arg] = current_args_stream
#         i += 1
#
#     return parsed_args


def get_positional_or_prompt(positionals, index, prompt_text, secure=False, double_check=False, count: Union[None, int]=1):
    """
    Gets the positional argument at the given index from positionals
    or asks the user to input it if not present between positionals.
    :param positionals: the positionals arguments
    :param index: the index of the argument
    :param prompt_text: the text eventually prompted to the user
    :param secure: whether the input should be hidden
    :param double_check: whether double check the secure input
    :param count: how many arguments take
    :return: the obtained value
    """
    if index >= len(positionals):
        return prompt(prompt_text, secure=secure, double_check=double_check, until_valid=True)

    if count == 1:
        return positionals[index] # standard case: 1 positional

    if count is None:
        return positionals[index:] # * positionals

    return positionals[index : index + count] # n positionals


def get_option_or_prompt(options, option_name, prompt_text, secure=False, double_check=False):
    """
    Gets the option value from options or asks the user to input it
    if not present between options.
    :param options: the parsed options
    :param option_name: the name of the option for which get the value
    :param prompt_text: the text eventually prompted to the user
    :param secure: whether the input should be hidden
    :param double_check: whether double check the secure input
    :return: the obtained value
    """
    return options.get(option_name) or \
           prompt(prompt_text, secure=secure, double_check=double_check, until_valid=True)


def get_option_or_default(options, option_name, default_value=None):
    """
    Gets the first option's value from options or returns the default value
    :param options: the parsed options
    :param option_name: the name of the option for which get the value
    :param default_value the value to return if the parameter is not present
    :return: the obtained value or the default value if the parameter if the argument
            is not present
    """
    return options.get(option_name) or default_value


def obtain_store_name(positionals):
    """
    Gets the store name if present in positionals or asks the user to input it
    if not present between positionals.
    :param positionals: the positionals arguments
    :return: the store name
    """
    return get_positional_or_prompt(positionals, 0, "Store name: ")


def obtain_store_key(options, keyring_store_name=None):
    """
    Gets the store key if present in options or asks the user to input it
    if not present between options.
    :param options: the parsed options
    :param keyring_store_name: the store name to use for eventually retrieve the
                                key from the keyring
    :return: the store key
    """
    # Check between arguments
    key = options.get(Options.STORE_KEY)

    if key:
        return key

    # Check for cached key
    if keyring_store_name:
        aeskey = keyring_get_key(keyring_store_name)
        if aeskey:
            return aeskey

    return get_option_or_prompt(options, Options.STORE_KEY,
                                "Store key: ", secure=True, double_check=False)


def obtain_stores_path(options, ensure_existence=True) -> Path:
    """
    Gets the store path if present in options or asks the user to input it
    if not present between parsed_args.
    :param options: the parsed arguments
    :param ensure_existence: whether abort if the path does not exist
    :return: the store path
    """
    path = Path(get_option_or_default(options, Options.STORE_PATH, DEFAULT_SECRETS_PATH))
    if ensure_existence and not path.exists():
        abort(f"Error: path does not exist ({path})")
    return path


def obtain_commons(positionals, options, ensure_existence=True, allow_keyring=True):
    """
    Gets the store path, name and key if present in parsed_args or
    asks the user to input them if not present between parsed_args.
    :param positionals: the positionals
    :param options: the options
    :param ensure_existence: whether abort if the path does not exist
    :param allow_keyring: whether the keyring should be used, unless --no-keyring is specified
    :return: a tuple with path, name and key
    """

    use_keyring = allow_keyring and not options.get(Options.NO_KEYRING)

    stores_path = obtain_stores_path(options, ensure_existence=ensure_existence)
    store_name = obtain_store_name(positionals)
    store_key = obtain_store_key(options, keyring_store_name=store_name if use_keyring else None)

    return stores_path, store_name, store_key, use_keyring


# =========================
# ======== COMMANDS =======
# =========================


def safe_execute_command(command, error_message="Unexpected error occurred"):
    command_ok = False
    try:
        command_ok = command()
    except Exception as e:
        logging.warning(f"Exception occurred\n{e}")
        logging.warning(traceback.format_exc())

    if not command_ok:
        abort(error_message)


def execute_create_store(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options,
                       ensure_existence=False,
                       allow_keyring=False)

    # Store fields
    raw_store_fields = options.get(Options.STORE_FIELDS)

    if raw_store_fields is None:
        raw_store_fields = []
        i = 1
        print("\n"
              "Insert store fields with format <name>[+<attr_1><attr_2>...].\n"
              "Available attributes are:\n"
              "+ m (mandatory)\n"
              "+ h (hidden)\n"
              "(Leave empty for terminate the fields insertion)\n")
        
        while True:
            f = input(f"{i} ° field: ")
            if not f:
                break

            raw_store_fields.append(f)
            i += 1

    store_fields = []
    for raw_field in raw_store_fields:
        field_parts = raw_field.split("+")
        fieldname = field_parts[0]
        fieldattributes = field_parts[1] if len(field_parts) > 1 else []

        store_fields.append(StoreField(
            fieldname,
            hidden=SecretAttributes.HIDDEN in fieldattributes,
            mandatory=SecretAttributes.MANDATORY in fieldattributes)
        )

    def do_create_store():
        store = Store(stores_path, store_name, store_key)
        store.add_fields(*store_fields)
        return store.save()

    safe_execute_command(
        do_create_store,
        error_message=f"Error: cannot create store '{store_name}'"
    )


def execute_destroy_store(positionals, options):
    stores_path = obtain_stores_path(options)
    store_name = obtain_store_name(positionals)

    def do_destroy_store():
        store = Store(stores_path, store_name)
        if not store.destroy():
            return False

        # Remind to delete the keyring
        keyring_del_key(store_name)

        return True

    safe_execute_command(
        do_destroy_store,
        error_message=f"Error: cannot destroy store '{store_name}'"
    )


def execute_list_stores(_, options):
    stores_path = obtain_stores_path(options, ensure_existence=False)

    if not stores_path.exists():
        logging.warning("Store path does not exists")
        return # not an error, just no stores

    for store_path in stores_path.iterdir():
        if store_path.suffix == STORE_EXTENSION:
            print(store_path.stem)


def execute_show_store(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options)

    def do_show_store():
        store = Store(stores_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)
        return store.show(table=not options.get(Options.NO_TABLE),
                          when=options.get(Options.WHEN))

    safe_execute_command(
        do_show_store,
        error_message=f"Error: cannot show store '{store_name}'"
    )


def execute_git_push(_, options):
    stores_path = obtain_stores_path(options)

    def do_push():
        commit_message = get_option_or_default(options, Options.GIT_MESSAGE)

        if not commit_message:
            commit_message = "Committed on " + datetime.datetime.now().strftime("%H:%M:%S %d/%m/%Y")

        logging.debug(f"Will push {stores_path} with message: {commit_message}")

        return gitsync.push(stores_path, commit_message)

    safe_execute_command(
        do_push,
        error_message="Error: cannot push"
    )


def execute_git_pull(_, options):
    store_path = obtain_stores_path(options)

    def do_pull():
        logging.debug(f"Will pull from to {store_path}")
        return gitsync.pull(store_path)

    safe_execute_command(
        do_pull,
        error_message="Error: cannot pull"
    )


def execute_change_store_key(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options)
    new_store_key = get_positional_or_prompt(positionals, 1, "New store key: ",
                                             secure=True, double_check=True)

    def do_change_store_key():
        store = Store(stores_path, store_name, store_key)
        store.open()

        new_store = Store(stores_path, store_name, new_store_key)
        new_store.clone_content(store)

        if not new_store.save():
            return False

        # Remind to delete the keyring
        keyring_del_key(store_name)

        return True

    safe_execute_command(
        do_change_store_key,
        error_message=f"Error: cannot change store key of store '{store_name}'"
    )


def execute_clear_store(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options)

    def do_clear_store():
        store = Store(stores_path, store_name, store_key)
        store.open()
        store.clear_secrets()
        return store.save()

    safe_execute_command(
        do_clear_store,
        error_message=f"Error: cannot clear store '{store_name}'"
    )


def execute_add_secret(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options)

    secret_data = options.get(Options.SECRET_DATA)

    def do_add_secret():
        store = Store(stores_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)

        if secret_data:
            secret = keyval_list_to_dict(secret_data.split(","))
            secret_fields = [k.lower() for k in secret.keys()]

            # If there are already some fields, ask only the mandatory
            # (since this is probably non interactive mode and we won't
            # block the execution)
            missing_fields = [f for f in store.fields
                              if f.mandatory and f.name.lower() not in secret_fields]
        else:
            secret = {}

            # Ask every field
            missing_fields = [f for f in store.fields]

        logging.debug(f"Missing fields to ask: {[f.name for f in missing_fields]}")

        for f in missing_fields:
            secret[f.name] = prompt(
                f.name + ": ",
                secure=f.hidden,
                double_check=True,
                double_check_prompt_text=f.name + " again: ",
                double_check_failed_message="Double check failed, please insert the field again",
                until_valid=f.mandatory)

        if not store.add_secrets(secret):
            return False

        return store.save()

    safe_execute_command(
        do_add_secret,
        error_message=f"Error: cannot add secret to store '{store_name}'"
    )


def execute_grep_secret(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options)

    grep_pattern = get_positional_or_prompt(positionals, 1, "Search pattern: ")

    def do_grep_secret():
        store = Store(stores_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)
        return store.grep(grep_pattern,
                          colors=not options.get(Options.NO_COLOR),
                          table=not options.get(Options.NO_TABLE),
                          when=options.get(Options.WHEN))

    safe_execute_command(
        do_grep_secret,
        error_message=f"Error: cannot search for secrets in store '{store_name}'"
    )


def execute_remove_secret(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options)

    raw_secrets_ids = get_positional_or_prompt(
        positionals, 1, "ID of the secret(s) to remove: ", count=None)

    # Convert to list if is a string (took with input())
    if isinstance(raw_secrets_ids, str):
        raw_secrets_ids = raw_secrets_ids.split(" ")

    secret_ids = [int(sid) for sid in raw_secrets_ids]

    def do_remove_secret():
        store = Store(stores_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)
        if not store.remove_secrets(*secret_ids):
            return False
        return store.save()

    safe_execute_command(
        do_remove_secret,
        error_message=f"Error: cannot remove secret(s) with ID(s) {secret_ids} from store '{store_name}'"
    )


def execute_modify_secret(positionals, options):
    stores_path, store_name, store_key, use_keyring = \
        obtain_commons(positionals, options)
    secret_id = int(get_positional_or_prompt(positionals, 1, "ID of the secret to modify: "))
    secret_data = options.get(Options.SECRET_DATA)

    def do_modify_secret():
        store = Store(stores_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)

        # Secret data
        if secret_data is None:
            secret_mod = {}

            secret = store.secret(secret_id)

            if not secret:
                abort("Error: invalid secret ID; index out of bound")

            logging.debug(f"Will modify secret {secret}")

            print("Which field to modify?")
            choice = len(store.fields)

            max_length = 0

            for f in store.fields:
                max_length = max(len(f.name), max_length)

            while choice >= len(store.fields):
                for i, f in enumerate(store.fields):
                    s = str(i) + ") " + f.name.ljust(max_length)
                    if f.name in secret:
                        s += " (" + (secret[f.name] if not f.hidden else "*" * len(secret[f.name])) + ")"
                    print(s)
                choice = int(input(": "))

            changed_field = store.fields[choice]
            newval = prompt(
                "New value of '" + changed_field.name + "': ",
                secure=changed_field.hidden,
                double_check=True,
                double_check_prompt_text="New value of '" + changed_field.name + "' again: ",
                double_check_failed_message="Double check failed, please insert the field again",
                until_valid=changed_field.mandatory)

            secret_mod[changed_field.name] = newval
        else:
            secret_mod = keyval_list_to_dict(secret_data.split(","))

        if not store.modify_secret(secret_id, secret_mod):
            return False

        return store.save()

    safe_execute_command(
        do_modify_secret,
        error_message=f"Error: cannot modify secret with ID {secret_id} from store '{store_name}'"
    )

def open_store(store, update_keyring=True):
    store.open()

    if update_keyring and not keyring_has_key(store.name):
        keyring_put_key(store.name, store.key)


COMMAND_DISPATCHER = {
    Commands.GIT_PUSH: execute_git_push,
    Commands.GIT_PULL: execute_git_pull,
    Commands.CREATE_STORE: execute_create_store,
    Commands.DESTROY_STORE: execute_destroy_store,
    Commands.LIST_STORES: execute_list_stores,
    Commands.SHOW_STORE: execute_show_store,
    Commands.CHANGE_STORE_KEY: execute_change_store_key,
    Commands.CLEAR_STORE: execute_clear_store,
    Commands.ADD_SECRET: execute_add_secret,
    Commands.GREP_SECRET: execute_grep_secret,
    Commands.REMOVE_SECRET: execute_remove_secret,
    Commands.MODIFY_SECRET: execute_modify_secret
}

def main():
    if len(sys.argv) <= 1:
        terminate(HELP)

    parser = argparse.ArgumentParser(
        description="encrypt and decrypt private data using AES",
        add_help=False
    )

    parser.add_argument("positionals",
                        nargs="*")

    parser.add_argument("-h", "--help",
                        action="store_true",
                        dest=Options.HELP)

    parser.add_argument("--version",
                        action="store_true",
                        dest=Options.VERSION)

    parser.add_argument("-p", "--path",
                        dest=Options.STORE_PATH)

    parser.add_argument("-k", "--key",
                        dest=Options.STORE_KEY)

    parser.add_argument("-v", "--verbose",
                        action="store_true",
                        dest=Options.VERBOSE)

    parser.add_argument("--no-keyring",
                        action="store_true",
                        dest=Options.NO_KEYRING)

    parser.add_argument("-f", "--fields",
                        dest=Options.STORE_FIELDS)

    parser.add_argument("--no-table",
                        action="store_true",
                        dest=Options.NO_TABLE)

    parser.add_argument("--no-color",
                        action="store_true",
                        dest=Options.NO_COLOR)

    parser.add_argument("-w", "--when",
                        action="store_true",
                        dest=Options.WHEN)

    parser.add_argument("-m", "--message",
                        dest=Options.GIT_MESSAGE)

    parser.add_argument("--data",
                        dest=Options.SECRET_DATA)


    args = vars(parser.parse_args(sys.argv[1:]))

    if args.get(Options.HELP):
        terminate(HELP)

    if args.get(Options.VERSION):
        terminate(f"{APP_NAME} {APP_VERSION}")

    init_logging(logging.DEBUG if args.get("verbose") else logging.CRITICAL)

    logging.info(f"Executing script with arguments: \n{args}")

    positionals = args.get("positionals")
    command = positionals[0]
    positionals = positionals[1:]

    if not command:
        abort(f"Error: command not provided")
    
    if command not in COMMAND_DISPATCHER:
        abort(f"Error: unknown command '{command}'")
        
    logging.info(f"Executing command '{command}'")

    try:
        COMMAND_DISPATCHER[command](positionals, args)
    except KeyboardInterrupt:
        logging.debug("CTRL+C: interrupted by user")
        exit(1)

if __name__ == "__main__":
    main()
