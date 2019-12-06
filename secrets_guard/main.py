import datetime
import logging
import os
import sys
import traceback

from secrets_guard import gitsync
from secrets_guard.args import Args
from secrets_guard.cli import Options, Commands, SecretAttributes
from secrets_guard.conf import Conf, LoggingLevels
from secrets_guard.keyring import keyring_get_key, keyring_put_key, keyring_has_key, keyring_del_key
from secrets_guard.store import Store, StoreField
from secrets_guard.utils import keyval_list_to_dict, abort, terminate, is_empty_string, prompt, is_string

HELP = """NAME 
    secrets - encrypt and decrypt private information (such as passwords)

SYNOPSIS
    secrets <COMMAND> [COMMAND_OPTIONS] [GENERAL_OPTIONS]
    
DESCRIPTION
    Stores and retrieves encrypted data to/from files.
    
    Each command can be used either in batch or interactive mode;
    each mandatory but not specified argument will be required interactively.
    
    One of the following command must be specified:
    
UTILITY COMMANDS

    help
        Shows this help message.
        
    version
        Shows the version number.
        
GLOBAL COMMANDS
                        
    list [--path <PATH>]
        List the names of the stores found at the path specified
        by --path (or at the default one if not specified).
    
        e.g. secrets list
 
STORE COMMANDS
        
    create [<STORE_NAME>] [--fields FIELDS] [--path <PATH>] [--key <STORE_KEY>]
        Creates a new store at the given path using the given key.
        The FIELDS must be expressed as a space separated list of field names.
        
        Furthermore some attributes can be expressed for the fields by appending
        "+<attr_code_1><attr_code_2>..." after the field name.
        
        The available attributes are
        1) h: hidden (the user input is not shown)
        2) m: mandatory (the field must contain a non empty string)
        
        e.g. secrets create password --fields Site Account Password Other --key mykey
        e.g. secrets create password --fields Site+m Account+m Password+mh Other --mykey
        
    destroy [<STORE_NAME>] [--path <PATH>]
        Destroys the store at the given path.
        
        e.g. secrets destroy password

    key [<STORE_NAME>] [<NEW_STORE_KEY>] [--path <PATH>] [--key <STORE_KEY>]
        Changes the key of the store from STORE_KEY to NEW_STORE_KEY.
        
        e.g. secrets key newkey --key currentkey
        
    clear [<STORE_NAME>] [--path <PATH>] [--key <STORE_KEY>]
        Clears the content (all the secrets) of a store.
        The model is left unchanged.
        
    show [<STORE_NAME>] [--path <PATH>] [--key <STORE_KEY>] [--no-table]
        Decrypts and shows the content of an entire store.
        
        e.g. secrets show password --key mykey
            
    grep [<STORE_NAME>] [<SEARCH_PATTERN>] [--path <PATH>] [--key <STORE_KEY>] [--no-color] [--no-table]
        Performs a regular expression search between the data of the store.
        The SEARCH_PATTERN can be any valid regular expression.
        The matches will be highlighted unless --no-color is specified.
        
        e.g. secrets grep password MyPass --key mykey
        e.g. secrets grep password "^My.*word" --key mykey
        
SECRET COMMANDS
        
    add [<STORE_NAME>] [--data DATA] [--path <PATH>] [--key <STORE_KEY>]
        Inserts a new secret into a store.
        The DATA must be expressed as a key=value list where the key should
        be a field of the store.
        
        e.g. secrets add password --data Site="Megavideo" Account="me@gmail.com" Password="MyPassword" --key mykey

    remove [<STORE_NAME>] [<SECRET_IDS>*] [--path <PATH>] [--key <STORE_KEY>]
        Removes the secret(s) with the given SECRET_IDS from the store.
        The SECRET_IDS should be retrieved using the secrets grep command.
        
        e.g. secrets remove password 12
        e.g. secrets remove password 12 14 15 7 11
    
    modify [<STORE_NAME>] [<SECRET_ID>] [--data DATA] [--path <PATH>] [--key <STORE_KEY>]
        Modifies the secret with the given SECRET_ID using the given DATA.
        The DATA must be expressed as a key=value list.
    
        e.g. secrets modify password 11 --data Password="MyNewPassword" --key mykey
               
GIT COMMANDS

    push [--path <PATH>] [--message <COMMIT_MESSAGE>] [--remote <REMOTE_NAME>]
        Commits and pushes to the remote git repository.
        Actually performs "git add ." , "git commit -m 'COMMIT_MESSAGE'" and
        "git push [REMOTE_NAME]" on the given path.
        Note that the action is related to the whole repository, 
        not a particular store.

        If the COMMIT_MESSAGE is not specified, a default commit message 
        will be created.
        If the REMOTE_NAME is not specified, the default one 
        (if set, e.g. via --set-upstream) will be used.
        The credentials might be required by the the invoked git push routine.
        
        e.g. secrets push
        e.g. secrets push --remote origin
        e.g. secrets push --remote bitbucket --message "Added Google password"
          
    pull [--remote <REMOTE_NAME>] [--path <PATH>]
        Pull from the remote git branch.
        Note that the action is related to the whole repository, 
        not a particular store.

        e.g. secrets pull --remote origin

GENERAL OPTIONS
    --verbose
        Prints debug statements.
    
    --no-keyring
        Do not use the keyring for retrieve the password.
        By default a password used for open a store is cached in the keyring
        for further uses."""


def init_logging(parsed_args):
    """ Initializes the logging. """

    logging.addLevelName(LoggingLevels.TRACE, "TRACE")

    def trace(message, *args, **kws):
        if logging.getLogger().isEnabledFor(LoggingLevels.TRACE):
            logging.log(LoggingLevels.TRACE, message, *args, **kws)

    logging.trace = trace
    logging.Logger.trace = trace

    logging.basicConfig(level=Conf.LOGGING_LEVEL,
                        format="[%(levelname)s] %(asctime)s %(message)s",
                        datefmt='%d/%m/%y %H:%M:%S',
                        stream=sys.stdout)

    if not parsed_args.has_kwarg(Options.VERBOSE):
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

    for command in Commands.__dict__.values():
        if command == command_request:
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


def obtain_positional_argument(parsed_args, index, prompt_text, secure=False, double_check=False, count=1):
    """
    Gets the positional argument at the given index from parsed_args
    or asks the user to input it if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param index: the index of the argument
    :param prompt_text: the text eventually prompted to the user
    :param secure: whether the input should be hidden
    :param double_check: whether double check the secure input
    :param count: how many arguments take
    :return: the obtained value
    """
    if len(parsed_args.args) > index:
        if not count:
            return parsed_args.args[index:]

        if count == 1:
            return parsed_args.args[index]

        return parsed_args.args[index:index + count]

    return prompt(prompt_text, secure=secure, double_check=double_check, until_valid=True)


def obtain_argument_params(parsed_args, argument, prompt_text, secure=False, double_check=False):
    """
    Gets the argument's params from parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param argument: the name of the argument for which get the params
    :param prompt_text: the text eventually prompted to the user
    :param secure: whether the input should be hidden
    :param double_check: whether double check the secure input
    :return: the obtained value
    """
    params = parsed_args.kwarg_params(argument)

    if params:
        return params

    return prompt(prompt_text, secure=secure, double_check=double_check, until_valid=True)


def obtain_argument_param(parsed_args, argument, prompt_text, secure=False, double_check=False):
    """
    Gets the first argument's param from parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param argument: the name of the argument for which get the params
    :param prompt_text: the text eventually prompted to the user
    :param secure: whether the input should be hidden
    :param double_check: whether double check the secure input
    :return: the obtained value
    """
    param = parsed_args.kwarg_param(argument)

    if param:
        return param

    return prompt(prompt_text, secure=secure, double_check=double_check, until_valid=True)


def obtain_optional_argument_param(parsed_args, argument, default_value=None):
    """
    Gets the first argument's param from parsed_args or returns the default value
    :param parsed_args: the parsed arguments
    :param argument: the name of the argument for which get the param
    :param default_value the value to return if the parameter is not present
    :return: the obtained value or the default value if the parameter if the argument
            is not present
    """
    param = parsed_args.kwarg_param(argument)

    if param:
        return param

    return default_value


def obtain_store_name(parsed_args):
    """
    Gets the store name if present in parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :return: the store name
    """
    return obtain_positional_argument(parsed_args, 0, "Store name: ") + Conf.STORE_EXTENSION


def obtain_store_key(parsed_args, keyring_store_nome=None):
    """
    Gets the store key if present in parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param keyring_store_nome: the store name to use for eventually retrieve the
                                key from the keyring
    :return: the store key
    """
    # Check between arguments
    key = parsed_args.kwarg_param(Options.STORE_KEY)

    if key:
        return key

    # Check for cached key
    if keyring_store_nome:
        aeskey = keyring_get_key(keyring_store_nome)
        if aeskey:
            return aeskey

    return obtain_argument_param(parsed_args, Options.STORE_KEY,
                                 "Store key: ", secure=True, double_check=False)


def obtain_store_path(parsed_args, ensure_existence=True):
    """
    Gets the store path if present in parsed_args or asks the user to input it
    if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param ensure_existence: whether abort if the path does not exist
    :return: the store path
    """
    path = parsed_args.kwarg_param(Options.STORE_PATH, Conf.DEFAULT_SECRETS_PATH)
    if ensure_existence and not os.path.exists(path):
        abort("Error: path does not exist (%s)" % path)
    return path


def obtain_common_store_arguments(parsed_args, ensure_valid_path=True, allow_keyring=True):
    """
    Gets the store path, name and key if present in parsed_args or
    asks the user to input them if not present between parsed_args.
    :param parsed_args: the parsed arguments
    :param ensure_valid_path: whether abort if the path does not exist
    :param allow_keyring: whether the keyring should be used, unledd --no-keyring is specified
    :return: a tuple with path, name and key
    """

    use_keyring = allow_keyring and not parsed_args.has_kwarg(Options.NO_KEYRING)

    path = obtain_store_path(parsed_args, ensure_existence=ensure_valid_path)
    name = obtain_store_name(parsed_args)
    key = obtain_store_key(parsed_args, keyring_store_nome=name if use_keyring else None)

    return path, name, key, use_keyring


# =========================
# ======== COMMANDS =======
# =========================


def attempt_execute_command(command, error_message="Unexpected error occurred"):
    command_ok = False
    try:
        command_ok = command()
    except Exception as e:
        logging.warning("Caught exception: %s", e)
        logging.warning(traceback.format_exc())

    if not command_ok:
        abort(error_message)


def execute_help(_):
    terminate(HELP)


def execute_version(_):
    terminate(Conf.APP_NAME + " " + Conf.APP_VERSION)


def execute_create_store(parsed_args):
    store_path, store_name, store_key, use_keyring = \
        obtain_common_store_arguments(parsed_args,
                                      ensure_valid_path=False,
                                      allow_keyring=False)

    # Store fields
    raw_store_fields = parsed_args.kwarg_params(Options.STORE_FIELDS)

    if raw_store_fields is None:
        raw_store_fields = []
        f = None
        i = 1
        print("\nInsert store fields with format <name>[+<properties>].\n(Leave empty for end the fields insertion).")
        while not is_empty_string(f):
            f = input(str(i) + "° field: ")
            if not is_empty_string(f):
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
        store = Store(store_path, store_name, store_key)
        store.add_fields(*store_fields)
        return store.save()

    attempt_execute_command(
        do_create_store,
        error_message="Error: cannot create store"
    )


def execute_destroy_store(parsed_args):
    store_path = obtain_store_path(parsed_args)
    store_name = obtain_store_name(parsed_args)

    def do_destroy_store():
        store = Store(store_path, store_name)
        if not store.destroy():
            return False

        # Remind to delete the keyring
        keyring_del_key(store_name)

        return True

    attempt_execute_command(
        do_destroy_store,
        error_message="Error: cannot destroy store"
    )


def execute_list_stores(parsed_args):
    store_path = obtain_store_path(parsed_args, ensure_existence=False)

    if not os.path.exists(store_path):
        logging.warning("Store path does not exists")
        # Not an error, just no stores
        return

    for filename in os.listdir(store_path):
        # Consider only store files
        if filename.endswith(Conf.STORE_EXTENSION):
            # Remove the extension
            print(filename.rsplit(Conf.STORE_EXTENSION, 1)[0])


def execute_show_store(parsed_args):
    store_path, store_name, store_key, use_keyring = obtain_common_store_arguments(parsed_args)

    def do_show_store():
        store = Store(store_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)
        return store.show(table=not parsed_args.has_kwarg(Options.NO_TABLE))

    attempt_execute_command(
        do_show_store,
        error_message="Error: cannot show store"
    )


# def execute_git_init(parsed_args):
#     store_path = obtain_store_path(parsed_args)
#
#     def do_init():
#         logging.debug("Will in at %s", store_path)
#         return gitsync.init(store_path)
#
#     attempt_execute_command(
#         do_init,
#         error_message="Error: cannot init"
#     )


def execute_git_push(parsed_args):
    store_path = obtain_store_path(parsed_args)
    remote_branch = obtain_optional_argument_param(parsed_args, Options.BRANCH)
    commit_message = obtain_optional_argument_param(parsed_args, Options.MESSAGE)

    def do_push():
        nonlocal commit_message

        logging.debug("Will push %s to branch %s", store_path, remote_branch)

        if not commit_message:
            commit_message = "Committed on " + datetime.datetime.now().strftime("%H:%M:%S %d/%m/%Y")

        return gitsync.push(store_path, commit_message, remote_branch)

    attempt_execute_command(
        do_push,
        error_message="Error: cannot push"
    )


def execute_git_pull(parsed_args):
    store_path = obtain_store_path(parsed_args)
    remote_branch = obtain_optional_argument_param(parsed_args, Options.BRANCH)

    def do_pull():
        logging.debug("Will pull from branch %s to %s", store_path, remote_branch)
        return gitsync.pull(store_path, remote_branch)

    attempt_execute_command(
        do_pull,
        error_message="Error: cannot pull"
    )


def execute_change_store_key(parsed_args):
    store_path, store_name, store_key, use_keyring = obtain_common_store_arguments(parsed_args)
    new_store_key = obtain_positional_argument(parsed_args, 1, "New store key: ",
                                               secure=True, double_check=True)

    def do_change_store_key():
        store = Store(store_path, store_name, store_key)
        store.open()

        new_store = Store(store_path, store_name, new_store_key)
        new_store.clone_content(store)

        if not new_store.save():
            return False

        # Remind to delete the keyring
        keyring_del_key(store_name)

        return True

    attempt_execute_command(
        do_change_store_key,
        error_message="Error: cannot change store key"
    )


def execute_clear_store(parsed_args):
    store_path, store_name, store_key, use_keyring = obtain_common_store_arguments(parsed_args)

    def do_clear_store():
        store = Store(store_path, store_name, store_key)
        store.open()
        store.clear_secrets()
        return store.save()

    attempt_execute_command(
        do_clear_store,
        error_message="Error: cannot clear store"
    )


def execute_add_secret(parsed_args):
    store_path, store_name, store_key, use_keyring = obtain_common_store_arguments(parsed_args)

    # Secret data

    secret_data = parsed_args.kwarg_params(Options.SECRET_DATA)

    def do_add_secret():
        store = Store(store_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)

        if secret_data is None:
            secret = {}
            for f in store.fields:
                secret[f.name] = prompt(
                    f.name + ": ", secure=f.hidden,
                    double_check=True,
                    double_check_prompt_text=f.name + " again: ",
                    double_check_failed_message="Double check failed, please insert the field again",
                    until_valid=f.mandatory)
        else:
            secret = keyval_list_to_dict(secret_data)
            # If there are already some fields, ask only the mandatory
            # (since this is probably non interactive mode and we won't
            # block the execution)
            for f in store.fields:
                if f.mandatory:
                    has_mandatory = False
                    for secfield in secret:
                        if f.name.lower() == secfield.lower():
                            has_mandatory = True
                            break
                    if not has_mandatory:
                        secret[f.name] = prompt(
                            f.name + ": ", secure=f.hidden,
                            double_check=True,
                            double_check_prompt_text=f.name + " again: ",
                            double_check_failed_message="Double check failed, please insert the field again",
                            until_valid=f.mandatory)

        if not store.add_secrets(secret):
            return False

        return store.save()

    attempt_execute_command(
        do_add_secret,
        error_message="Error: cannot add secret"
    )


def execute_grep_secret(parsed_args):
    store_path, store_name, store_key, use_keyring = obtain_common_store_arguments(parsed_args)
    grep_pattern = obtain_positional_argument(parsed_args, 1, "Search pattern: ")

    def do_grep_secret():
        store = Store(store_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)
        return store.grep(grep_pattern,
                          colors=not parsed_args.has_kwarg(Options.NO_COLOR),
                          table=not parsed_args.has_kwarg(Options.NO_TABLE))

    attempt_execute_command(
        do_grep_secret,
        error_message="Error: cannot search for secrets"
    )


def execute_remove_secret(parsed_args):
    store_path, store_name, store_key, use_keyring = obtain_common_store_arguments(parsed_args)

    raw_secrets_ids = obtain_positional_argument(
        parsed_args, 1, "ID of the secret(s) to remove: ", count=None)

    # Convert to list if is a string (took with input())
    if is_string(raw_secrets_ids):
        raw_secrets_ids = raw_secrets_ids.split(" ")

    secret_ids = [int(sid) for sid in raw_secrets_ids]

    def do_remove_secret():
        store = Store(store_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)
        if not store.remove_secrets(*secret_ids):
            return False
        return store.save()

    attempt_execute_command(
        do_remove_secret,
        error_message="Error: cannot remove secrets with ID %s (index out of bound?)" % secret_ids
    )


def execute_modify_secret(parsed_args):
    store_path, store_name, store_key, use_keyring = obtain_common_store_arguments(parsed_args)
    secret_id = int(obtain_positional_argument(parsed_args, 1, "ID of the secret to modify: "))
    secret_data = parsed_args.kwarg_params(Options.SECRET_DATA)

    def do_modify_secret():
        store = Store(store_path, store_name, store_key)
        open_store(store, update_keyring=use_keyring)

        # Secret data
        if secret_data is None:
            secret_mod = {}

            secret = store.secret(secret_id)

            if not secret:
                abort("Error: invalid secret ID; index out of bound")

            logging.debug("Will modify secret %s", secret)

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
                "New value of '" + changed_field.name + "': ", secure=changed_field.hidden,
                double_check=True,
                double_check_prompt_text="New value of '" + changed_field.name + "' again: ",
                double_check_failed_message="Double check failed, please insert the field again",
                until_valid=changed_field.mandatory)

            secret_mod[changed_field.name] = newval
        else:
            secret_mod = keyval_list_to_dict(secret_data)

        if not store.modify_secret(secret_id, secret_mod):
            return False

        return store.save()

    attempt_execute_command(
        do_modify_secret,
        error_message="Error: cannot modify secret with ID %d (index out of bound?)" % secret_id
    )


def execute_command(parsed_args):
    if parsed_args is None or parsed_args.command is None:
        abort("Error: invalid arguments (command not specified)")

    dispatcher = {
        Commands.HELP: execute_help,
        Commands.VERSION: execute_version,
        # Commands.GIT_INIT: execute_git_init,
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

    if parsed_args.command not in dispatcher:
        abort("Error: unknown command request '%s'" % parsed_args.command)
    logging.debug("Executing command '" + parsed_args.command + "'")

    try:
        dispatcher[parsed_args.command](parsed_args)
    except KeyboardInterrupt:
        logging.debug("Interrupted by user")
        exit(-1)


def open_store(store, update_keyring=True):
    if update_keyring:
        open_store_updating_keyring(store)
    else:
        store.open()


def open_store_updating_keyring(store):
    store.open()
    if not keyring_has_key(store.name):
        keyring_put_key(store.name, store.key, is_plain_key=store.has_plain_key())


def main():
    if len(sys.argv) <= 1:
        terminate(HELP)

    args = parse_arguments(sys.argv[1:])

    init_logging(args)

    logging.info("Executing script with arguments: \n%s", args)

    execute_command(args)


if __name__ == "__main__":
    main()
