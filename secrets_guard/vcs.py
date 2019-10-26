import logging
import subprocess

from git import Repo


def git_run(*args):
    # subprocess.run([, stdout=subprocess.STDOUT, stderr=subprocess.STDOUT)
    run_args = ["git"] + list(args)
    print("run_args", run_args)
    proc = subprocess.run(run_args, capture_output=True, universal_newlines=True)
    print(proc.stdout)


def push(local_path, remote_branch, commit_message):
    """
    Commits and push the store to the remote git branch
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

    if not remote_branch:
        logging.error("Remote branch must be specified")
        return False

    logging.debug("Locating repo at path: %s", local_path)
    repository = Repo(local_path)

    if not repository:
        logging.error("Not a git repository, cannot push")
        return False

    # logging.debug("Adding . to stage")
    # # repository.index.add(".")
    git_run("add", ".")
    #
    # logging.debug("Committing with message: %s", commit_message)
    # # repository.index.commit(commit_message)
    git_run("commit", "-m", commit_message)

    logging.debug("Pushing to branch %s", remote_branch)
    # remote = repository.remote(name=remote_branch)
    #
    # if not remote or not remote.exists():
    #     logging.error("Cannot find remote branch named %s", remote_branch)
    #     return False
    #
    # def progress_handler(op_code, cur_count, max_count=None, message=''):
    #     print("Progress: %d out of %d | %s", cur_count, max_count, message)
    #
    # logging.debug("Really invoking push()")
    # remote.push(progress=progress_handler)
    # repository.git.push(remote_branch)

    git_run("push")

    return True
