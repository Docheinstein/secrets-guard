import base64
import hashlib
import sys
from pathlib import Path

from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad


def aes_key(key: str | bytes):
    """
    Returns a valid AES key from a string or
    returns the key itself if it's already an AES key.
    """
    if isinstance(key, bytes):
        return key

    if isinstance(key, str):
        return hashlib.sha256(key.encode()).digest()

    raise TypeError(f"Invalid key type: {type(key)}, expect str or bytes")


def aes_encrypt(plaintext: str, iv: bytes, key: str | bytes):
    """
    Encrypts a text using the given IV and key
    (saving the IV at the beginning of the file).
    """
    key = aes_key(key)

    padded_text = pad(bytes(plaintext, encoding="utf-8"), AES.block_size)
    cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    return base64.b64encode(iv + cipher.encrypt(padded_text))


def aes_decrypt(encrypted_content: bytes, key: str | bytes):
    """
    Decrypts an encrypted content using the given key
    (looking for the IV at the beginning of the file).
    """
    key = aes_key(key)

    decoded_content = base64.b64decode(encrypted_content)
    iv = decoded_content[:AES.block_size]
    body = decoded_content[AES.block_size:]

    cipher = AES.new(key, mode=AES.MODE_CBC, IV=iv)
    return unpad(cipher.decrypt(body), AES.block_size).decode("utf-8")


def aes_encrypt_file(path: Path, key: str | bytes, content: str):
    """ Encrypts a file using AES (saving the IV at the beginning of the file). """
    try:
        with path.open("wb") as f:
            iv = Random.new().read(AES.block_size)
            encrypted_content = aes_encrypt(content, iv, aes_key(key))
            f.write(encrypted_content)
        return True
    except OSError as e:
        print(f"ERROR: AES encryption error {e}", file=sys.stderr)
        return False


def aes_decrypt_file(path: Path, key: str | bytes):
    """ Decrypts a file using AES (looking for the IV at the beginning of the file). """
    try:
        with path.open("rb") as file:
            encrypted_content = file.read()
            plaintext = aes_decrypt(encrypted_content, aes_key(key))
            return plaintext
    except OSError as e:
        print(f"ERROR: AES decryption error {e}", file=sys.stderr)
        return False
    except:
        print(f"ERROR: AES decryption error (invalid key?)", file=sys.stderr)
        return False
