import random
import unittest

from secrets_guard.crypt import aes_encrypt_file, aes_decrypt_file
from secrets_guard.utils import random_string


class AesTests(unittest.TestCase):
    def test_encrypt_decrypt(self):
        F = "/tmp/test.sec"

        for i in range(1000):
            original_content = random_string(random.randint(1, 1024))
            key = random_string()
            aes_encrypt_file(F, key, original_content)
            decrypted_content = aes_decrypt_file(F, key)
            self.assertEqual(decrypted_content, original_content)


if __name__ == "__main__":
    unittest.main()





