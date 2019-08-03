import logging
import random
import string
import sys
from sys import exit


def eprint(*args, **kwargs):
    """
    Prints to stderr.
    :param args: arguments argument to pass to print()
    :param kwargs: keyword argument to pass to print()
    """
    print(*args, file=sys.stderr, **kwargs)


def terminate(message, exit_code=0):
    """
    Exit gracefully with the given message and exit code.
    :param message: the message to print to stdout before exit
    :param exit_code: the exit code
    """
    print(message)
    exit(exit_code)


def abort(message, exit_code=-1):
    """
    Exit ungracefully with the given message and exit code.
    :param message: the message to print to stderr before exit
    :param exit_code: the exit code
    """
    logging.error(message)
    eprint(message)
    exit(exit_code)


def random_string(length=10, alphabet=string.ascii_lowercase):
    """
    Generate a random string of the given length.
    :param length: the length of the random string to generate
    :param alphabet: a string containing the alphabet to use for the generation.
                     Default is string.ascii_lowercase
    :return: the randomly generated string
    """
    return ''.join(random.choice(alphabet) for _ in range(length))


def is_empty_string(s):
    """
    Returns whether the given string is empty
    :param s: the string
    :return: whether the string is empty
    """
    return s == ""


def list_to_str(l, sep=", "):
    """
    Joins the elements of the list using the given separator.
    :param l: the list
    :param sep: the separator to use for join elements
    :return: the joined string
    """
    if l is None:
        return ""
    return sep.join(l)


def dict_of_lists_to_str(d, sep=": "):
    """
    Returns a string representation of a dictionary of lists.
    :param d: the dictionary
    :param sep: the separator
    :return: the string representation
    """
    if d is None:
        return "<none>"
    s = ""
    for k in d:
        s += k
        if len(d[k]) > 0:
            s += sep + list_to_str(d[k]) + " | "
    return s


def keyval_list_to_dict(l):
    """
    Converts a list of key=value strings to a dictionary.
    :param l: the list
    :return: the dictionary
    """
    d = {}
    for e in l:
        keyval = e.split("=", 2)
        if len(keyval) != 2:
            return None
        d[keyval[0]] = keyval[1]
    return d


def tabulate_enum(headers, data, enum_field_name="ID"):
    """
    Returns a string representation of the given data list using the given headers.
    Furthermore add a column used for enumerate rows.
    :param headers: a list of strings representing the headers
    :param data: a list of objects with the properties specified in headers
    :param enum_field_name: the name of the header used for enumerate the rows
    :return: the table string of the data
    """
    headers.insert(0, enum_field_name)

    for i, d in enumerate(data):
        if enum_field_name not in d:
            d[enum_field_name] = i

    return tabulate(headers, data)


def tabulate(headers, data):
    """
    Returns a string representation of the given data list using the given headers.
    :param headers: a list of strings representing the headers
    :param data: a list of objects with the properties specified in headers
    :return: the table string of the data
    """
    HALF_PADDING = 1
    PADDING = 2 * HALF_PADDING

    out = ""

    max_lengths = {}

    # Compute max length for each field
    for h in headers:
        m = len(h)
        for d in data:
            if h in d:
                m = max(m, len(str(d[h])))
        max_lengths[h] = m

    def separator_row(newline=True):
        s = ""
        for hh in headers:
            s += "+" + ("-" * (max_lengths[hh] + PADDING))
        s += "+"

        if newline:
            s += "\n"

        return s

    def data_cell(filler):
        return (" " * HALF_PADDING) + filler() + (" " * HALF_PADDING)

    # Row
    out += separator_row()

    # Headers
    for h in headers:
        out += "|" + data_cell(lambda: h.ljust(max_lengths[h]))
    out += "|\n"

    # Row
    out += separator_row()

    # Data
    for d in data:
        for dh in headers:
            out += "|" + data_cell(
                lambda: (str(d[dh]) if dh in d else " ").ljust(max_lengths[dh]))
        out += "|\n"

    # Row
    out += separator_row(newline=False)

    return out

