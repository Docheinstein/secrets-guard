import logging

from git import Repo


def git_progress_handler(_op_code_, cur_count, max_count=None, message=''):
    print("Progress: {} / {} {}".format(cur_count, max_count, message))


def print_if_valid(something):
    if something:
        print(something)


# def init(local_path):
#     """
#     Initializes the local path as a git repository (git init)
#     :param local_path: the local path of the repository
#     :return: whether the path as been initialized as a git repository
#     """
#     if not local_path:
#         logging.error("Local path must be specified")
#         return False
#
#     logging.debug("Locating repo at path: %s", local_path)
#     repository = Repo(local_path)
#
#     if not repository:
#         logging.error("Not a git repository")
#         return False
#
#     repository.git.init()
#
#     return True


def push(local_path, commit_message, remote_branch=None):
    """
    Commits and push the local path (containing the stores) to the remote git branch
    :param local_path local repository path
    :param remote_branch remote branch name
    :param commit_message the commit message
    :return: whether the push has been performed
    """
    if not local_path:
        logging.error("Local path must be specified")
        return False

    if not commit_message:
        logging.error("A commit message must be specified")
        return False

    # if not remote_branch:
    #     logging.error("Remote branch must be specified")
    #     return False

    logging.debug("Locating repo at path: %s", local_path)
    repository = Repo(local_path)

    if not repository:
        logging.error("Not a git repository, cannot push")
        return False

    logging.debug("Adding . to stage")
    print_if_valid(repository.git.add("."))

    # Before commit, check if commit is needed, otherwise
    # an exception will be thrown

    repo_status = repository.git.status("-s")
    logging.debug("git status -s report is:\n%s", repo_status)
    if repo_status:
        logging.debug("Committing with message: %s", commit_message)
        print_if_valid(repository.git.commit("-m", commit_message))
        # repository.index.commit(commit_message)
    else:
        logging.debug("No commit is needed")

    logging.debug("Will push to branch %s", remote_branch)

    # remote = repository.remote(name=remote_branch)
    # if not remote or not remote.exists():
    #     logging.error("Cannot find remote branch named %s", remote_branch)
    #     return False
    # pushed = remote.push(progress=git_progress_handler)

    logging.debug("Really invoking push()")

    if remote_branch:
        print_if_valid(repository.git.push(remote_branch))
    else:
        print_if_valid(repository.git.push())

    return True


def pull(local_path, remote_branch):
    """
    Pulls from the remote git branch to the local path of the stores
    :param local_path local repository path
    :param remote_branch remote branch name
    :return: whether the pull has been performed
    """
    if not local_path:
        logging.error("Local path must be specified")
        return False

    # if not remote_branch:
    #     logging.error("Remote branch must be specified")
    #     return False

    logging.debug("Locating repo at path: %s", local_path)
    repository = Repo(local_path)

    if not repository:
        logging.error("Not a git repository, cannot pull")
        return False

    logging.debug("Will pull from branch %s", remote_branch)

    # remote = repository.remote(name=remote_branch)
    # if not remote or not remote.exists():
    #     logging.error("Cannot find remote branch named %s", remote_branch)
    #     return False

    logging.debug("Really invoking pull()")

    if remote_branch:
        print_if_valid(repository.git.pull(remote_branch))
    else:
        print_if_valid(repository.git.pull())

    return True
