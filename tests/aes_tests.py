import random
import string
import tempfile
import unittest

from Cryptodome import Random
from Cryptodome.Cipher import AES

from secrets_guard.aes import aes_encrypt_file, aes_decrypt_file, aes_encrypt, aes_decrypt


def random_string(length=10, alphabet=string.ascii_lowercase):
    return ''.join(random.choice(alphabet) for _ in range(length))

class AesTests(unittest.TestCase):

    ITERS = 256

    def test_encrypt_decrypt(self):
        for i in range(AesTests.ITERS):

            original_text = random_string(random.randint(1, 8192))
            key = random_string(random.randint(1, 50))
            iv = Random.new().read(AES.block_size)

            cipher_text = aes_encrypt(original_text, iv, key)

            decrypted_text = aes_decrypt(cipher_text, key)

            self.assertEqual(original_text, decrypted_text)

    def test_encrypt_decrypt_file(self):
        fd, fname = tempfile.mkstemp()

        for i in range(AesTests.ITERS):
            original_text = random_string(random.randint(1, 8192))
            key = random_string(random.randint(1, 50))

            aes_encrypt_file(fname, key, original_text)
            decrypted_text = aes_decrypt_file(fname, key)

            self.assertEqual(original_text, decrypted_text)


if __name__ == "__main__":
    unittest.main()





