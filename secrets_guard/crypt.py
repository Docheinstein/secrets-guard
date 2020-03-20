import base64
import hashlib
import logging

from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


def aes_key(key):
    """
    Generate a valid AES key from a string.
    :param key: the key from which generate an AES key
    :return: the AES key
    """
    return hashlib.sha256(key.encode()).digest()


def aes_encrypt(plaintext, iv, key, is_plain_key=True):
    """
    Encrypts a text using the given IV and key
    (saving the IV at the beginning of the file).
    :param plaintext: the text to encrypt
    :param iv: the AES initialization vector
    :param key: the key
    :param is_plain_key: whether the key is plaintext or is already hashed
    :return: the encrypted content
    """
    key = aes_key(key) if is_plain_key else key

    padded_text = pad(bytes(plaintext, encoding="utf-8"), AES.block_size)
    cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    return base64.b64encode(iv + cipher.encrypt(padded_text))


def aes_decrypt(encrypted_content, key, is_plain_key=True):
    """
    Decrypts an encrypted content using the given key
    (looking for the IV at the beginning of the file).
    :param encrypted_content: the encrypted content (as b64 text)
    :param key: the key
    :param is_plain_key: whether the key is plaintext or is already hashed
    :return: the plaintext
    """

    key = aes_key(key) if is_plain_key else key

    decoded_content = base64.b64decode(encrypted_content)
    iv = decoded_content[:AES.block_size]
    body = decoded_content[AES.block_size:]

    cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    return unpad(cipher.decrypt(body), AES.block_size).decode("utf-8")


def aes_encrypt_file(path, key, content, is_plain_key=True):
    """
    Encrypts a file using AES (saving the IV at the beginning of the file).
    :param path: the path where store the encrypted file
    :param key: the key
    :param content: the plaintext
    :param is_plain_key: whether the key is plaintext or is already hashed
    :return: whether the file has been encrypted successfully
    """

    try:
        with open(path, "wb") as file:
            iv = Random.new().read(AES.block_size)
            encrypted_content = aes_encrypt(content, iv, key, is_plain_key=is_plain_key)
            file.write(encrypted_content)
        return True
    except OSError as e:
        logging.error("AES I/O error", e)
        return False


def aes_decrypt_file(path, key, is_plain_key=True):
    """
    Decrypts a file using AES (looking for the IV at the beginning of the file).
    :param path: the path of the file to decrypt
    :param key: the key
    :return: whether the file has been decrypted successfully
    :param is_plain_key: whether the key is plaintext or is already hashed
    """
    try:
        with open(path, "rb") as file:
            encrypted_content = file.read()
            plaintext = aes_decrypt(encrypted_content, key, is_plain_key=is_plain_key)
            return plaintext
    except OSError as e:
        logging.error("AES I/O error", e)
        return False
    except UnicodeError:
        logging.error("AES decrypt error (invalid key?)")
        return False
