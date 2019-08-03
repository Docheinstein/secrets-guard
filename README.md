SECRETS GUARD
====

Encrypts and decrypts private information, written in Python3.

## DESCRIPTION

Secrets Guard is a tool for encrypt and decrypt any kind of information.  
The idea is create a store with a given model and then insert 'secrets' inside it.   
It's similar the Linux tool `pass`, but uses AES instead of GPG and allows to create general purpose store containing any king of info, not only passwords.

## REQUIREMENTS

Requires at least Python 3.  
Requires 'Crypto' library.

## INSTALLATION

```
pip3 install secrets-guard
```

The script can be used with `python3 -m secrets_guard ...`.  
Along with the installation via pip, a script called `secrets` will be
installed, which is a shortcut for `python3 -m secrets_guard`.


## USAGE

Each command works either in interactive or batch mode, depending on the 
provided arguments.  
For example, if the `key` is not provided with `--key` it will be asked to the user.

### Store commands

#### create
First of all, a store should be created using the command `create`.  
For example, for create a basic password store with the name 'password':

```
secrets create password --fields Site Account Password Other --key mykey
```

#### destroy
A store can be destroyed with `destroy`.

```
secrets destroy password
```

#### list
For list all the store within a path (the default if not specified with `--path`)
the `list` command can be used.

```
secrets list
```

#### show
The entire content of a store can be seen using `show`.

```
secrets show password --key mykey
```

### Secret commands

#### add
A secret can be added to an existent store using `add` as follows:

```
secrets add password --data Site="Megavideo" Account="me@gmail.com" Password="MyPassword" --key mykey
```

#### grep
For search between the secrets' fields for a specific word (or regular expression) the command `grep` can be used.

```
secrets grep password MyPass --key mykey
```
```
secrets grep password "^My.*word" --key mykey
```

#### remove
A secret can be removed from a store using `remove`.  
The ID of the secret to remove must be specified (it can be retrieved with `grep` or `show`).

```
secrets remove password 12
```

#### modify
The fields of a secret can be changed using `modify` as follows:

```
secrets modify password 11 --data Password="MyNewPassword" --key mykey
```

## HELP
For more details about the commands, use `help`:

```
NAME 
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
        Prints debug statements.
``` 


## LICENSE
Secrets Guard is [MIT licensed](./LICENSE).