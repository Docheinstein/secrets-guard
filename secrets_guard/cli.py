# Gather all the arguments recognized by the command line


class Commands:
    """
    Secrets Guard commands.
    """

    GIT_PUSH = "push"
    GIT_PULL = "pull"
    CREATE_STORE = "create"
    DESTROY_STORE = "destroy"
    LIST_STORES = "list"
    SHOW_STORE = "show"
    CHANGE_STORE_KEY = "key"
    CLEAR_STORE = "clear"
    ADD_SECRET = "add"
    GREP_SECRET = "grep"
    REMOVE_SECRET = "remove"
    MODIFY_SECRET = "modify"


class Options:
    """
    Secrets Guard options (prefixed with --).
    """

    STORE_FIELDS = "fields"
    STORE_KEY = "key"
    STORE_PATH = "path"
    SECRET_DATA = "data"

    GIT_MESSAGE = "message"

    HELP = "help"
    VERSION = "version"

    VERBOSE = "verbose"
    NO_COLOR = "no-color"
    NO_TABLE = "no-table"
    NO_KEYRING = "no-keyring"
    WHEN = "when"
    SORT = "sort"
    RSORT = "rsort"


class SecretAttributes:
    """
    Recognized secrets' attributes.
    """
    HIDDEN = "h"
    MANDATORY = "m"
