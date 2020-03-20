import random
import tempfile
import unittest

from Crypto import Random
from Crypto.Cipher import AES

from secrets_guard.crypt import aes_encrypt_file, aes_decrypt_file, aes_encrypt, aes_decrypt
from secrets_guard.utils import random_string


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





