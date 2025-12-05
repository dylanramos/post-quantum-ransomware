from client import Client


def main():
    print("=== Post-Quantum Ransomware ===\n")
    client = Client()

    while True:

        print("1. Encrypt files")
        print("2. Pay ransom")
        print("3. Unlock one file")
        print("4. Change password")

        selection = input("\nSelect an option (1-4): ")

        if selection == "1":
            client.encrypt_files()
            print("The files have been encrypted.\n")
        elif selection == "2":
            print("Paying ransom...")
        elif selection == "3":
            print("Unlocking one file...")
        elif selection == "4":
            print("Changing password...")
        else:
            print("Invalid selection. Please choose a valid option.")


if __name__ == "__main__":
    main()
