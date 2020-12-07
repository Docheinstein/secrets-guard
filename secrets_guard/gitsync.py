import logging

from git import Repo


def print_if_valid(something):
    if something:
        print(something)

def push(local_path, commit_message):
    """
    Commits and push the local path (containing the stores) to the remote git branch
    :param local_path local repository path
    :param commit_message the commit message
    :return: whether the push has been performed
    """
    if not local_path:
        logging.error("Local path must be specified")
        return False

    if not commit_message:
        logging.error("A commit message must be specified")
        return False

    logging.debug(f"Locating local repo at path: {local_path}")
    repository = Repo(local_path)

    if not repository:
        logging.error("Not a git repository, cannot push")
        return False

    logging.debug("Adding . to stage")
    print_if_valid(repository.git.add("."))

    # Before commit, check if commit is needed, otherwise
    # an exception will be thrown
    repo_status = repository.git.status("-s")
    logging.debug(f"git status -s report is:\n{repo_status}")
    if repo_status:
        logging.debug(f"Committing with message: {commit_message}")
        print_if_valid(repository.git.commit("-m", commit_message))
    else:
        logging.debug("No commit is needed")

    # Actually push
    logging.debug("Will push...")
    print_if_valid(repository.git.push())

    return True


def pull(local_path):
    """
    Pulls from the remote git branch to the local path of the stores
    :param local_path local repository path
    :return: whether the pull has been performed
    """
    if not local_path:
        logging.error("Local path must be specified")
        return False

    logging.debug(f"Locating repo at path: {local_path}")
    repository = Repo(local_path)

    if not repository:
        logging.error("Not a git repository, cannot pull")
        return False

    logging.debug("Will pull...")
    print_if_valid(repository.git.pull())

    return True
