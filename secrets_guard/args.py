from secrets_guard.utils import list_to_str, dict_of_lists_to_str


class Args:
    """
    Encapsulated parsed arguments.
    This contains
    1) The command (e.g. create/show/...)
    2) Positional arguments (e.g. the id for remove <ID>)
    3) Keyword arguments (e.g. --key <KEY>)
    """

    def __init__(self):
        self.command = None
        self.args = []
        self.kwargs = {}

    def __str__(self):
        s = "COMMAND: " + (self.command if self.command is not None else "<none>") + "\n" + \
            "Args: " + list_to_str(self.args) + "\n" + \
            "Kwargs: " + dict_of_lists_to_str(self.kwargs)

        return s

    def add_kwarg_param(self, arg, param):
        """
        Adds a param to a keyword argument.
        :param arg: the argument
        :param param: the param to add
        """
        if arg not in self.kwargs:
            self.kwargs[arg] = []

        self.kwargs[arg].append(param)

    def kwarg_params(self, arg, default=None):
        """
        Returns the params of the given keyword argument.
        :param arg: the argument
        :param default: the value to return if the argument does not exist
        :return: the params of the argument or the default value
        """
        return self.kwargs.get("--" + arg, default)

    def kwarg_param(self, arg, default=None):
        """
        Returns the first param of the given keyword argument.
        :param arg: the argument
        :param default: the value to return if the argument does not exist
        :return: the params of the argument or the default value
        """
        real_arg = "--" + arg
        if real_arg not in self.kwargs:
            return default

        params = self.kwargs.get("--" + arg)
        if not params:
            return None
        if len(params) <= 0:
            return None
        return params[0]

    def has_kwarg(self, arg):
        """
        Returns whether the given keyword argument is present.
        :param arg: the argument
        :return: whether the argument is present
        """

        return ("--" + arg) in self.kwargs
