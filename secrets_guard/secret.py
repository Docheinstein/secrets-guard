import logging
import re

# from secrets_guard.store import
from secrets_guard.utils import tabulate_enum


# A 'secret' is an entity that contains the information specified
# for the store it belongs to.
# A collection of secrets compose a 'store'.
# For example, a simple password secret may contain the fields
# "Site", "Account", "Password".

#
# def secret_apply_change(store_fields, secret, secret_mod):
#     """
#     For each known field of store_fields push the value from secret_mod
#     to secret.
#     :param store_fields: the known store fields (each field outside of those
#                          will be ignored
#     :param secret: the secret
#     :param secret_mod: the secret modification (may contain only some fields)
#     """
#     for store_field in store_fields:
#         for mod_field in secret_mod:
#             if store_field.lower() == mod_field.lower():
#                 secret[store_field] = secret_mod[mod_field]
#
# #
# # def secret_add(store_path, store_name, store_key, secret):
# #     """
# #     Adds a secret to a store.
# #     :param store_path: the folder of the store
# #     :param store_name: the store name
# #     :param store_key: the key to use for unlock the store
# #     :param secret: the secret to add to the store
# #     :return: whether the secret has been added successfully
# #     """
# #     logging.info("Adding secret to store '%s' at path '%s' (%s)",
# #                  store_name, store_path, secret)
# #
# #     def do_secret_add(store):
# #         # Check the real secret's fields and add the new secret
# #         # keeping only the valid fields
# #         safe_secret = {}
# #         secret_apply_change(store["fields"], safe_secret, secret)
# #         logging.debug("Adding secret: %s", safe_secret)
# #         store["data"].append(safe_secret)
# #         return True
# #
# #     return store_manage_write(store_path, store_name, store_key, do_secret_add)
# #
# #
# # def secret_remove(store_path, store_name, store_key, secret_id):
# #     """
# #     Removes a secret from the store
# #     :param store_path: the folder of the store
# #     :param store_name: the store name
# #     :param store_key: the key to use for unlock the store
# #     :param secret_id: the index of the secret to remove (must be a valid index)
# #     :return: whether the secret has been removed successfully
# #     """
# #     logging.info("Removing secret [%d] from store '%s' at path '%s'",
# #                  secret_id, store_name, store_path)
# #
# #     def do_secret_remove(store):
# #         if not secret_id < len(store["data"]):
# #             logging.error("Invalid secret id; out of bound")
# #             return False
# #
# #         del store["data"][secret_id]
# #         return True
# #
# #     return store_manage_write(store_path, store_name, store_key, do_secret_remove)
#
#
# def secret_grep(store_path, store_name, store_key, grep_pattern):
#     """
#     Performs a regular expression between each field of each secret and
#     prints the matches a tabular data.
#     :param store_path: the folder of the store
#     :param store_name: the store name
#     :param store_key: the key to use for unlock the store
#     :param grep_pattern: the search pattern as a valid regular expression
#     :return: whether the secret has been grep-ed successfully
#     """
#     logging.info("Grepping secret from store '%s' at path '%s' using pattern %s",
#                  store_name, store_path, grep_pattern)
#
#     def do_secret_grep(store):
#         matches = []
#         for d in store["data"]:
#             for i, f in enumerate(d):
#                 logging.debug("Comparing %s against %s", f, grep_pattern)
#                 if re.search(grep_pattern, d[f]):
#                     logging.debug("Found match: %s", d)
#                     d["ID"] = i
#                     matches.append(d)
#                     break
#         logging.debug("There are %d matches", len(matches))
#         print(tabulate_enum(store["fields"], matches, "ID"))
#         # logging.info("\n" + tabulate_enum(store["fields"], matches, "ID"))
#         return True
#
#     return store_manage_read(store_path, store_name, store_key, do_secret_grep)
#
#
# def secret_modify(store_path, store_name, store_key, secret_id, new_secret):
#     """
#     Modifies the secret with the given secret_id applying the modification
#     contained in new_secret.
#     :param store_path: the folder of the store
#     :param store_name: the store name
#     :param store_key: the key to use for unlock the store
#     :param secret_id: the index of the secret to modify (must be a valid index)
#     :param new_secret: the secret modification (may contain only some fields)
#     :return:
#     """
#     logging.info("Modifying secret [%d] from store '%s' at path '%s' with mod: %s",
#                  secret_id, store_name, store_path, new_secret)
#
#     def do_secret_modify(store):
#         if not secret_id < len(store["data"]):
#             logging.error("Invalid secret id; out of bound")
#             return False
#
#         secret = store["data"][secret_id]
#         secret_apply_change(store["fields"], secret, new_secret)
#         return True
#
#     return store_manage_write(store_path, store_name, store_key, do_secret_modify)
#
#

