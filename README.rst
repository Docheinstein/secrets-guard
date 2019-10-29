SECRETS GUARD
=============

Encrypts and decrypts private information, written in Python3.

DESCRIPTION
-----------

Secrets Guard is a tool for encrypt and decrypt any kind of information.

The idea is create a store with a given model and then insert 'secrets' inside it.

It's similar the Linux tool ``pass``, but uses AES instead of GPG and allows to create general purpose store containing any king of info, not only passwords.

REQUIREMENTS
------------

Requires at least Python 3.

Requires 'pycryptodome' library.

INSTALLATION
------------

::

    pip3 install secrets-guard

The script can be used with ``python3 -m secrets_guard ...``.

Along with the installation via pip, a script called ``secrets`` will be installed, which is a shortcut for ``python3 -m secrets_guard``.

USAGE
-----

Each command works either in interactive or batch mode, depending on the provided arguments.

For example, if the ``key`` is not provided with ``--key`` it will be asked to the user.

Global commands
~~~~~~~~~~~~~~~

list
^^^^

For list all the store within a path (the default if not specified with ``--path``) the ``list`` command can be used.

::

    secrets list


Store commands
~~~~~~~~~~~~~~

create
^^^^^^

First of all, a store should be created using the command ``create``.

For example, for create a basic password store with the name 'password':

::

    secrets create password --fields Site Account Password Other --key mykey

destroy
^^^^^^^

A store can be destroyed with ``destroy``.

::

    secrets destroy password

key
^^^

Changes the key of the store.

::

    secrets key password newkey --key oldkey

clear
^^^^^

Removes all the secrets from a store.

::

    secrets clear password --key mykey

show
^^^^

The entire content of a store can be seen using ``show``.

::

    secrets show password --key mykey

grep
^^^^

For search between the secrets' fields for a specific word (or regular expression) the command ``grep`` can be used.

::

    secrets grep password MyPass --key mykey

::

    secrets grep password "^My.*word" --key mykey

Secret commands
~~~~~~~~~~~~~~~

add
^^^

A secret can be added to an existent store using ``add`` as follows:

::

    secrets add password --data Site="Megavideo" Account="me@gmail.com" Password="MyPassword" --key mykey

remove
^^^^^^

A secret can be removed from a store using ``remove``.

The ID of the secret to remove must be specified (it can be retrieved with ``grep`` or ``show``).

::

    secrets remove password 12

modify
^^^^^^

The fields of a secret can be changed using ``modify`` as follows:

::

    secrets modify password 11 --data Password="MyNewPassword" --key mykey

HELP
----

For more details about the commands, use ``help``:

::

    NAME
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
            for further uses.

LICENSE
-------

Secrets Guard is `MIT licensed <./LICENSE>`__.
