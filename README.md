# Post-quantum Ransomware

This repository contains a mini-project for the Advanced Applied Cryptography (CAA) course, focused on developing a post-quantum ransomware in Python. The project statement can be found [here](/docs/statement.pdf).

## Documentation

The [report.pdf](/docs/report.pdf) (redacted in French) provides a detailed explanation of the implementation, including the cryptographic schemes used and the overall architecture of the ransomware.

## Setup

1. Go to the `src` directory:

   ```bash
   cd src
   ```
2. Run [init.sh](/src/init.sh) to create the test directory and populate it with files:

   ```bash
   chmod +x init.sh
   ./init.sh
   ```
3. Create a virtual environment:

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
4. Install the required dependencies:

   ```bash
    pip install -r requirements.txt
    ```
5. Run the application:

   ```bash
   python3 main.py
   ```

### Changing the test directory

To change the directory containing the files to be encrypted/decrypted, modify the `DIRECTORY_NAME` variable in `client.py` to point to your desired directory.

### Changing the dictionary path

To change the dictionary used for password generation, modify the `DICTIONARY_PATH` variable in `client.py` to point to your desired dictionary file.
