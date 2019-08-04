class Commands:
    """
    Available commands.
    """

    HELP = "help"
    CREATE_STORE = "create"
    DESTROY_STORE = "destroy"
    LIST_STORES = "list"
    SHOW_STORE = "show"
    ADD_SECRET = "add"
    GREP_SECRET = "grep"
    REMOVE_SECRET = "remove"
    MODIFY_SECRET = "modify"


class Options:
    """
    Available options.
    """

    STORE_FIELDS = "fields"
    STORE_KEY = "key"
    STORE_PATH = "path"
    SECRET_DATA = "data"
    VERBOSE = "verbose"


class SecretAttributes:
    HIDDEN = "h"
    MANDATORY = "m"
