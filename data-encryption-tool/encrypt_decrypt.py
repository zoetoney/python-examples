from cryptography.fernet import Fernet
import argparse
import os

# Generate or load a key
def load_key():
    key_path = "secret.key"
    if not os.path.exists(key_path):
        key = Fernet.generate_key()
        with open(key_path, "wb") as key_file:
            key_file.write(key)
    else:
        with open(key_path, "rb") as key_file:
            key = key_file.read()
    return key

# Encrypt file
def encrypt_file(file_name, key):
    if not os.path.exists(file_name):
        print(f"{file_name} not found. Creating with default content.")
        with open(file_name, 'w') as file:
            file.write("This is a default secret message.")

    fernet = Fernet(key)
    with open(file_name, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)

    encrypted_path = file_name + ".enc"
    with open(encrypted_path, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

    print(f"Encrypted file saved as {encrypted_path}")

# Decrypt file
def decrypt_file(file_name, key):
    if not os.path.exists(file_name):
        print(f"Encrypted file {file_name} not found. Decryption aborted.")
        return

    fernet = Fernet(key)
    with open(file_name, 'rb') as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)

    decrypted_path = file_name.replace('.enc', '')
    with open(decrypted_path, 'wb') as dec_file:
        dec_file.write(decrypted)

    print(f"Decrypted file saved as {decrypted_path}")

# Command-line interface
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="File Encryption and Decryption Tool")
    parser.add_argument("mode", choices=['encrypt', 'decrypt'], help="Operation mode")
    parser.add_argument("file", help="File to encrypt or decrypt")

    args = parser.parse_args()

    key = load_key()

    if args.mode == "encrypt":
        encrypt_file(args.file, key)
    elif args.mode == "decrypt":
        decrypt_file(args.file, key)