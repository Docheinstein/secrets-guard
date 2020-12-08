SECRETS GUARD
====

Encrypts and decrypts private information, written in Python3.

## DESCRIPTION

Secrets Guard is a tool for encrypt and decrypt any kind of information.  
The idea is create a store with a given model and then insert 'secrets' inside it.   
It's similar the Linux tool `pass`, but uses AES instead of GPG and allows to create general purpose store containing any kind of info, not only passwords.

## REQUIREMENTS

Requires at least Python 3.  
Requires 'pycryptodomex' library.

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

### Global commands

#### list
For list all the store within a path (the default if not specified with `--path`)
the `list` command can be used.

```
secrets list
```

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


#### key
Changes the key of the store.

```
secrets key password newkey --key oldkey
```

#### clear
Removes all the secrets from a store.

```
secrets clear password --key mykey
```

#### show
The entire content of a store can be seen using `show`.

```
secrets show password --key mykey
```

#### grep
For search between the secrets' fields for a specific word (or regular expression) the command `grep` can be used.

```
secrets grep password MyPass --key mykey
```
```
secrets grep password "^My.*word" --key mykey
```

### Secret commands

#### add
A secret can be added to an existent store using `add` as follows:

```
secrets add password --data Site="Megavideo" Account="me@gmail.com" Password="MyPassword" --key mykey
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

### GIT Commands

For keep the local repository synchronized with a remote GIT repository, the following commands can be used.
(The repository should already be initialized and configured properly).

The whole repository can be pushed with `push`:

```
secrets push --message "Added Google Drive password"
```

And can be pulled with `pull`:

```
secrets pull
```

## HELP
For more details about the commands, use `help`:

```

``` 


## LICENSE
Secrets Guard is [MIT licensed](./LICENSE).