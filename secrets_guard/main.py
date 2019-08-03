import logging
import os
import sys

from secrets_guard.apis import Options, Command
from secrets_guard.args import Args
from secrets_guard.conf import Conf
from secrets_guard.secret import secret_add, secret_remove, secret_grep, secret_modify
from secrets_guard.store import store_create, store_show, store_open, store_destroy
from secrets_guard.utils import keyval_list_to_dict, abort, terminate, is_empty_string

HELP = """NAME 
    secrets - encrypt and decrypt private information (such as passwords)

SYNOPSIS
    secrets <COMMAND> [COMMAND_OPTIONS] [OTHER_OPTIONS]
    
DESCRIPTION
    Stores and retrieves encrypted data to/from files.
    
    Each command can be used either in batch or interactive mode;
    each mandatory but not specified argument will be required interactively.
    
    One of the following command must be specified:
    
COMMANDS
    help
        Shows this help message.
        
    create [<STORE_NAME>] [--fields FIELDS] [--path <PATH>] [--key <STORE_KEY>]
        Creates a new store at the given path using the given key.
        The FIELDS must be expressed as a list of field names.
        
        e.g. secrets create password --fields Site Account Password Other --key mykey
        
    destroy [<STORE_NAME>] [--path <PATH>]
        Destroys the store at the given path.
        
        e.g. secrets destroy password
                
    list [--path <PATH>]
        List the names of the stores found at the path specified
        by --path (or at the default one if not specified).
    
        e.g. secrets list
        
    show [<STORE_NAME>] [--path <PATH>] [--key <STORE_KEY>]
        Decrypts and shows the content of an entire store.
        
        e.g. secrets show password --key mykey
        
    add [<STORE_NAME>] [--data DATA] [--path <PATH>] [--key <STORE_KEY>]
        Inserts a new secret into a store.
        The DATA must be expressed as a key=value list.
        
        e.g. secrets add password --data Site="Megavideo" Account="me@gmail.com" Password="MyPassword" --key mykey
    
    grep [<STORE_NAME>] [<SEARCH_PATTERN>] [--path <PATH>] [--key <STORE_KEY>]
        Performs a regular expression search between the data of the store.
        The SEARCH_PATTERN can be any valid regular expression.
        
        e.g. secrets grep password MyPass --key mykey
        e.g. secrets grep password "^My.*word" --key mykey
        
    remove [<STORE_NAME>] [<SECRET_ID>] [--path <PATH>] [--key <STORE_KEY>]
        Removes the secret with the given SECRET_ID from the store.
        The SECRET_ID should be retrieved using the secrets grep command.
        
        e.g. secrets remove password 12
    
    modify [<STORE_NAME>] [<SECRET_ID>] [--data DATA] [--path <PATH>] [--key <STORE_KEY>]
        Modifies the secret with the given SECRET_ID using the given DATA.
        The DATA must be expressed as a key=value list.
    
        e.g. secrets modify password 11 --data Password="MyNewPassword" --key mykey
        
OPTIONS
    --verbose
        Prints debug statements."""


def init_logging(parsed_args):
    """ Initializes the logging. """
    logging.basicConfig(level=Conf.LOGGING_LEVEL,
                        format="[%(levelname)s] %(asctime)s %(message)s",
                        datefmt='%d/%m/%y %H:%M:%S')

    if not parsed_args.has_kwarg(Options.VERBOSE.value):
        logging.disable()

# =====================
# ===== ARGUMENTS =====
# =====================


def parse_arguments(arguments):
    """
    Parses the argument list.
    :param arguments: the arguments to parse (sys.argv)
    :return: the parsed arguments
    """
    # logging.debug("Parsing arguments %s", arguments)

    parsed_args = Args()

    if len(arguments) < 1:
        abort("Error: the command must be specified")

    # Parse command

    command_request = arguments[0]

    for command in Command:
        if command.value == command_request:
            parsed_args.command = command

    if parsed_args.command is None:
        abort("Error: unknown command '%s'" % command_request)

    # Parse position/keyword arguments

    i = 1
    current_args_stream = parsed_args.args

    while i < len(arguments):
        arg = arguments[i]
        if not arg.startswith("--"):
            # Parameter of the current argument
            # logging.debug("Adding parameter %s to current argument", arg)
            current_args_stream.append(arg)
        else:
            # New argument
            # logging.debug("Found new argument: %s", arg)
            current_args_stream = []
            parsed_args.kwargs[arg] = current_args_stream
        i += 1

    return parsed_args


def obtain_positional_argument(parsed_args, index, prompt_text):
    """
    Gets the positional argument at the given index from parsed_args
    or asks the user to input it if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param index: the index of the argument
    :param prompt_text: the text eventually prompted to the user
    :return: the obtained value
    """
    if len(parsed_args.args) > index:
        return parsed_args.args[index]

    return input(prompt_text)


def obtain_argument_params(parsed_args, argument, prompt_text):
    """
    Gets the argument's params from parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param argument: the name of the argument for which get the params
    :param prompt_text: the text eventually prompted to the user
    :return: the obtained value
    """
    params = parsed_args.kwarg_params(argument)

    if params:
        return params

    return input(prompt_text)


def obtain_argument_param(parsed_args, argument, prompt_text):
    """
    Gets the first argument's param from parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param argument: the name of the argument for which get the params
    :param prompt_text: the text eventually prompted to the user
    :return: the obtained value
    """
    params = parsed_args.kwarg_param(argument)

    if params:
        return params

    return input(prompt_text)


def obtain_store_name(parsed_args):
    """
    Gets the store name if present in parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :return: the store name
    """
    return obtain_positional_argument(parsed_args, 0, "Store name: ") + Conf.STORE_EXTENSION


def obtain_store_key(parsed_args):
    """
    Gets the store key if present in parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :return: the store key
    """
    return obtain_argument_param(parsed_args, Options.STORE_KEY.value, "Store key: ")


def obtain_store_path(parsed_args, ensure_existence=True):
    """
    Gets the store path if present in parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param ensure_existence: whether abort if the path does not exist
    :return: the store path
    """
    path = parsed_args.kwarg_param(Options.STORE_PATH.value, Conf.DEFAULT_PATH)
    if ensure_existence and not os.path.exists(path):
        abort("Error: path does not exist (%s)" % path)
    return path


def obtain_common_store_arguments(parsed_args, ensure_valid_path=True):
    """
    Gets the store path, name and key if present in parsed_args or
    asks the user to input them if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param ensure_valid_path: whether abort if the path does not exist
    :return: a tuple with path, name and key
    """
    path = obtain_store_path(parsed_args, ensure_existence=ensure_valid_path)
    name = obtain_store_name(parsed_args)
    key = obtain_store_key(parsed_args)

    return path, name, key


# =========================
# ======== COMMANDS =======
# =========================


def attempt_execute_command(command, error_message="Unexpected error occurred"):
    command_ok = False
    try:
        command_ok = command()
    except Exception as e:
        logging.debug("Caught exception %s", e)

    if not command_ok:
        abort(error_message)


def execute_help(_):
    terminate(HELP)


def execute_create_store(parsed_args):
    store_path, store_name, store_key = \
        obtain_common_store_arguments(parsed_args, ensure_valid_path=False)

    # Store fields
    store_fields = parsed_args.kwarg_params(Options.STORE_FIELDS.value)

    if store_fields is None:
        store_fields = []
        f = None
        i = 1
        print("\nInsert store fields (leave empty for end the fields insertion).")
        while not is_empty_string(f):
            f = input(str(i) + "° field name: ")
            if not is_empty_string(f):
                store_fields.append(f)
            i += 1

    attempt_execute_command(
        lambda: store_create(store_path, store_name, store_key, *store_fields),
        error_message="Error: cannot create store"
    )


def execute_destroy_store(parsed_args):
    store_path = obtain_store_path(parsed_args)
    store_name = obtain_store_name(parsed_args)

    attempt_execute_command(
        lambda: store_destroy(store_path, store_name),
        error_message="Error: cannot destroy store"
    )


def execute_list_stores(parsed_args):
    store_path = obtain_store_path(parsed_args)

    for filename in os.listdir(store_path):
        # Consider only store files
        if filename.endswith(Conf.STORE_EXTENSION):
            # Remove the extension
            print(filename.rsplit(Conf.STORE_EXTENSION, 1)[0])


def execute_show_store(parsed_args):
    store_path, store_name, store_key = obtain_common_store_arguments(parsed_args)

    attempt_execute_command(
        lambda: store_show(store_path, store_name, store_key),
        error_message="Error: cannot show store"
    )


def execute_add_secret(parsed_args):
    store_path, store_name, store_key = obtain_common_store_arguments(parsed_args)

    # Secret data

    secret_data = parsed_args.kwarg_params(Options.SECRET_DATA.value)

    if secret_data is None:
        secret = {}
        store = store_open(store_path, store_name, store_key)

        for f in store["fields"]:
            secret[f] = input(f + ": ")
    else:
        secret = keyval_list_to_dict(secret_data)

    attempt_execute_command(
        lambda: secret_add(store_path, store_name, store_key, secret),
        error_message="Error: cannot add secret"
    )


def execute_grep_secret(parsed_args):
    store_path, store_name, store_key = obtain_common_store_arguments(parsed_args)
    grep_pattern = obtain_positional_argument(parsed_args, 1, "Search pattern: ")

    attempt_execute_command(
        lambda: secret_grep(store_path, store_name, store_key, grep_pattern),
        error_message="Error: cannot search for secrets"
    )


def execute_remove_secret(parsed_args):
    store_path, store_name, store_key = obtain_common_store_arguments(parsed_args)
    secret_id = int(obtain_positional_argument(parsed_args, 1, "ID of the secret to remove: "))

    attempt_execute_command(
        lambda: secret_remove(store_path, store_name, store_key, secret_id),
        error_message="Error: cannot remove secret with ID %d (index out of bound?)" % secret_id
    )


def execute_modify_secret(parsed_args):
    store_path, store_name, store_key = obtain_common_store_arguments(parsed_args)
    secret_id = int(obtain_positional_argument(parsed_args, 1, "ID of the secret to modify: "))
    secret_data = parsed_args.kwarg_params(Options.SECRET_DATA.value)

    # Secret data
    if secret_data is None:
        secret_mod = {}
        store = store_open(store_path, store_name, store_key)

        if secret_id >= len(store["data"]):
            abort("Error: invalid secret ID; index out of bound")

        secret = store["data"][secret_id]

        print("Which field to modify?")
        choice = len(store["fields"])

        while choice >= len(store["fields"]):
            for i, f in enumerate(store["fields"]):
                s = str(i) + ") " + f
                if f in secret:
                    s = str(s.ljust(14)) + "(" + secret[f] + ")"
                print(s)
            choice = int(input(": "))

        newval = input("New value of '" + store["fields"][choice] + "': ")
        secret_mod[store["fields"][choice]] = newval
    else:
        secret_mod = keyval_list_to_dict(secret_data)

    attempt_execute_command(
        lambda: secret_modify(store_path, store_name, store_key, secret_id, secret_mod),
        error_message="Error: cannot remove secret with ID %d (index out of bound?)" % secret_id
    )


def execute_command(parsed_args):
    if parsed_args is None or parsed_args.command is None:
        abort("Error: invalid arguments (command not specified)")

    dispatcher = {
        Command.HELP: execute_help,
        Command.CREATE_STORE: execute_create_store,
        Command.DESTROY_STORE: execute_destroy_store,
        Command.LIST_STORES: execute_list_stores,
        Command.SHOW_STORE: execute_show_store,
        Command.ADD_SECRET: execute_add_secret,
        Command.GREP_SECRET: execute_grep_secret,
        Command.REMOVE_SECRET: execute_remove_secret,
        Command.MODIFY_SECRET: execute_modify_secret
    }

    if parsed_args.command not in dispatcher:
        abort("Error: unknown command request '%s'" % parsed_args.command.value)
    logging.debug("Executing command '" + parsed_args.command.value + "'")

    try:
        dispatcher[parsed_args.command](parsed_args)
    except KeyboardInterrupt:
        pass


def main():
    if len(sys.argv) <= 1:
        terminate(HELP)

    args = parse_arguments(sys.argv[1:])

    init_logging(args)

    logging.info("Executing script for arguments: \n%s", args)

    execute_command(args)


if __name__ == "__main__":
    main()
