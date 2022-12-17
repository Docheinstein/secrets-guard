from git import Repo


def git_push(path, commit_message):
    repository = Repo(path)

    if not repository:
        print("ERROR: cannot push; not a git repository")
        return False

    repository.git.add(".")

    repo_status = repository.git.status("-s")

    if repo_status:
        repository.git.commit("-m", commit_message)
        repository.git.push()

    return True


def git_pull(path):
    repository = Repo(path)

    if not repository:
        return False

    repository.git.pull()

    return True
