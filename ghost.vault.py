import os
import argparse
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

MAGENTA = '\033[1;95m'
CYAN = '\033[1;96m'
YELLOW = '\033[1;93m'
BLUE = '\033[1;94m'
GREEN = '\033[1;92m'
WHITE = '\033[1;97m'
RED = '\033[1;91m'
ENDC = '\033[0m'

PASSWORD_HASH_SALT_FILE_NAME = ".password_hash_salt"
PASSWORD_HASH_FILE_NAME = ".password_hash"
PASSWORD_HASH_ITERATIONS = 200000 # More iterations for password hashing

# --- Constants ---
SALT_FILE_NAME = ".vault_salt"
VAULT_DIR_PREFIX = ""
ITERATIONS = 100000  # Number of iterations for PBKDF2HMAC for encryption key derivation
KEY_SIZE = 32  # 256-bit key for AES

# --- Helper Functions ---

def _hash_password(password, salt):
    """Hashes a password using PBKDF2HMAC for storage and verification."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE, # Use same key size for password hash
        salt=salt,
        iterations=PASSWORD_HASH_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def _derive_key(password, salt):
    """Derives a cryptographic key from a password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def _generate_salt():
    """Generates a random salt."""
    return os.urandom(16)

def _encrypt_data(data, key):
    """Encrypts data using AES in CBC mode."""
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend IV to ciphertext

def _decrypt_data(encrypted_data_with_iv, key):
    """Decrypts data using AES in CBC mode."""
    iv = encrypted_data_with_iv[:16]
    encrypted_data = encrypted_data_with_iv[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

def _verify_password(password, vault_path):
    """
    Verifies the entered password against the stored password hash in the vault.
    Returns True if the password is correct, False otherwise.
    """
    try:
        with open(os.path.join(vault_path, PASSWORD_HASH_SALT_FILE_NAME), "rb") as f:
            password_hash_salt = f.read()
        with open(os.path.join(vault_path, PASSWORD_HASH_FILE_NAME), "rb") as f:
            stored_password_hash = f.read()
    except FileNotFoundError:
        print(f" {RED}Error: Password hash files not found in vault. Vault might be corrupted.{ENDC}")
        return False

    entered_password_hash = _hash_password(password, password_hash_salt)
    return entered_password_hash == stored_password_hash

# --- Main Tool Functions ---

def create_vault(vault_name):
    """
    Creates a new secure vault directory.
    Prompts for a password and saves a salt file within the vault.
    """
    vault_path = VAULT_DIR_PREFIX + vault_name
    if os.path.exists(vault_path):
        print(f" {RED}Error: {CYAN}{vault_name} {RED}already exists.{ENDC}")
        return

    os.makedirs(vault_path)
    print(f" Vault directory {CYAN}/ghost-vault/{vault_path}/{ENDC} created.")

    password = getpass.getpass(" Enter a password for the vault > ")
    confirm_password = getpass.getpass(" Confirm password > ")

    if password != confirm_password:
        print(f" {RED}Error: Passwords do not match. Vault creation failed.{ENDC}")
        os.rmdir(vault_path)  # Clean up created directory
        return

    # Generate salt for encryption key derivation
    encryption_salt = _generate_salt()
    with open(os.path.join(vault_path, SALT_FILE_NAME), "wb") as f:
        f.write(encryption_salt)

    # Generate salt for password hashing and hash the password
    password_hash_salt = _generate_salt()
    hashed_password = _hash_password(password, password_hash_salt)

    with open(os.path.join(vault_path, PASSWORD_HASH_SALT_FILE_NAME), "wb") as f:
        f.write(password_hash_salt)
    with open(os.path.join(vault_path, PASSWORD_HASH_FILE_NAME), "wb") as f:
        f.write(hashed_password)

    print(f" {CYAN}{vault_name} {GREEN}created successfully. {YELLOW}Remember your password!{ENDC}")

def add_to_vault(vault_name, item_to_add_path):
    """
    Encrypts a file or recursively encrypts contents of a directory and adds it to the specified vault.
    The original item (file or directory) is deleted after successful encryption.
    """
    vault_path = VAULT_DIR_PREFIX + vault_name
    if not os.path.isdir(vault_path):
        print(f" {RED}Error: {YELLOW}{vault_name} {RED}does not exist.{ENDC}")
        return

    password = getpass.getpass(f" Enter password for {CYAN}{vault_name}{ENDC} > ")

    if not _verify_password(password, vault_path):
        print(f" {RED}Access Denied: Invalid password for {CYAN}{vault_name}{ENDC}")
        return

    try:
        with open(os.path.join(vault_path, SALT_FILE_NAME), "rb") as f:
            encryption_salt = f.read()
    except FileNotFoundError:
        print(f" {RED}Error: Encryption salt file not found in {CYAN}{vault_name} {RED}Vault might be corrupted.{ENDC}")
        return

    key = _derive_key(password, encryption_salt)

    if os.path.isfile(item_to_add_path):
        _encrypt_and_delete_file(item_to_add_path, vault_path, key)
    elif os.path.isdir(item_to_add_path):
        _encrypt_and_delete_directory(item_to_add_path, vault_path, key)
    else:
        print(f" {RED}Error: {YELLOW}{item_to_add_path} {RED}Is not a correct file path.{ENDC}")

def _encrypt_and_delete_file(filepath, vault_path, key):
    try:
        with open(filepath, "rb") as f_in:
            file_data = f_in.read()

        encrypted_data = _encrypt_data(file_data, key)

        relative_path = os.path.relpath(filepath, start=os.path.dirname(filepath))
        encrypted_filename = relative_path + ".enc"

        target_filepath = os.path.join(vault_path, encrypted_filename)
        os.makedirs(os.path.dirname(target_filepath), exist_ok=True)

        with open(target_filepath, "wb") as f_out:
            f_out.write(encrypted_data)

        os.remove(filepath)
        print(f" {WHITE}{filepath}{ENDC} encrypted and moved to vault as {MAGENTA}{encrypted_filename}{ENDC}")
    except Exception as e:
        print(f" {RED}Error processing {WHITE}{filepath}{ENDC} {e}")

def _encrypt_and_delete_directory(dirpath, vault_path, key):
    print(f" Encrypting and moving directory {BLUE}{dirpath}{ENDC} to vault...")
    base_dir_name = os.path.basename(dirpath)
    vault_target_dir = os.path.join(vault_path, base_dir_name)
    os.makedirs(vault_target_dir, exist_ok=True)

    for root, _, files in os.walk(dirpath):
        for file in files:
            filepath = os.path.join(root, file)
            relative_path = os.path.relpath(filepath, start=dirpath)

            target_filepath = os.path.join(vault_target_dir, relative_path + ".enc")
            os.makedirs(os.path.dirname(target_filepath), exist_ok=True)

            try:
                with open(filepath, "rb") as f_in:
                    file_data = f_in.read()
                encrypted_data = _encrypt_data(file_data, key)
                with open(target_filepath, "wb") as f_out:
                    f_out.write(encrypted_data)
                os.remove(filepath)
                print(f"  Encrypted and moved {WHITE}{filepath}{ENDC}")
            except Exception as e:
                print(f"  {RED}Error processing {WHITE}{filepath}{ENDC} {e}")

    # Remove the original (now empty) directory and its subdirectories
    try:
        os.removedirs(dirpath)
        print(f" Original directory {BLUE}{dirpath}{ENDC} and its contents removed.")
    except OSError as e:
        print(f" {RED}Error removing original directory {BLUE}{dirpath}{ENDC} {e}")


def retrieve_file_from_vault(vault_name, encrypted_filename, output_path=None):
    """
    Decrypts a file from the specified vault and moves it to the output path.
    The encrypted file is removed from the vault after successful decryption.
    """
    vault_path = VAULT_DIR_PREFIX + vault_name
    encrypted_file_path = os.path.join(vault_path, encrypted_filename)

    if not os.path.isdir(vault_path):
        print(f" {RED}Error: {YELLOW}{vault_name} {RED}does not exist.{ENDC}")
        return

    if not os.path.isfile(encrypted_file_path):
        print(f" {RED}Error: Encrypted file {YELLOW}{encrypted_filename} {RED}not found in {CYAN}{vault_name}{ENDC}")
        return

    password = getpass.getpass(f" Enter password for {CYAN}{vault_name}{ENDC} > ")

    if not _verify_password(password, vault_path):
        print(f" {RED}Access Denied: Invalid password for {CYAN}{vault_name}{ENDC}")
        return

    try:
        with open(os.path.join(vault_path, SALT_FILE_NAME), "rb") as f:
            encryption_salt = f.read()
    except FileNotFoundError:
        print(f" {RED}Error: Encryption salt file not found in {CYAN}{vault_name} {RED}Vault might be corrupted.{ENDC}")
        return

    key = _derive_key(password, encryption_salt)

    with open(encrypted_file_path, "rb") as f_in:
        encrypted_data = f_in.read()

    try:
        decrypted_data = _decrypt_data(encrypted_data, key)
    except Exception as e:
        print(f" {RED}Error: Could not decrypt file. Incorrect password or corrupted file. Details:{ENDC} {e}")
        return

    if output_path is None:
        # Default to current directory, remove .enc extension
        original_filename = os.path.splitext(encrypted_filename)[0]
        output_path = os.path.join(os.getcwd(), original_filename)

    with open(output_path, "wb") as f_out:
        f_out.write(decrypted_data)

    # Remove the encrypted file from the vault
    os.remove(encrypted_file_path)

    print(f" {MAGENTA}{encrypted_filename}{ENDC} decrypted from {CYAN}{vault_name}{ENDC} and moved to {WHITE}{output_path}{ENDC}")

def list_vault_contents(vault_name):
    """
    Lists the encrypted files within a specified vault.
    """
    vault_path = VAULT_DIR_PREFIX + vault_name
    if not os.path.isdir(vault_path):
        print(f" {RED}Error: {YELLOW}{vault_name} {RED}does not exist.{ENDC}")
        return

    print(f" Contents of {CYAN}{vault_name}{ENDC}")
    found_files = False
    for item in os.listdir(vault_path):
        if item != SALT_FILE_NAME and item.endswith(".enc"):
            print(f"   {MAGENTA}{item}{ENDC}")
            found_files = True
    if not found_files:
        print(f"  {YELLOW}(No encrypted files found){ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description="A tool to create password-protected directories (vaults) and manage encrypted files."
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Create Vault command
    create_parser = subparsers.add_parser("create", help="Create a password protected directory or vault to store encrypted files.")
    create_parser.add_argument("vault_name", type=str, help="Name of the vault to create.")

    # Add File/Directory command
    add_parser = subparsers.add_parser("add", help="Encrypt and move a file to a vault (include the full path of the file).")
    add_parser.add_argument("vault_name", type=str, help="Name of the vault.")
    add_parser.add_argument("item_to_add", type=str, help="Path to the file to encrypt and move.")

    # Retrieve File command
    retrieve_parser = subparsers.add_parser("retrieve", help="Decrypt and move a file from a vault to a chosen path or the current directory by default.")
    retrieve_parser.add_argument("vault_name", type=str, help="Name of the vault.")
    retrieve_parser.add_argument("encrypted_filename", type=str, help="Name of the encrypted file in the vault (e.g., 'my_doc.txt.enc').")
    retrieve_parser.add_argument("output_path", type=str, nargs='?', default=None, help="Optional: Path where the decrypted file will be saved. Defaults to current directory.")

    # List Vault Contents command
    list_parser = subparsers.add_parser("list", help="List encrypted files in a vault.")
    list_parser.add_argument("vault_name", type=str, help="Name of the vault.")

    args = parser.parse_args()

    if args.command == "create":
        create_vault(args.vault_name)
    elif args.command == "add":
        add_to_vault(args.vault_name, args.item_to_add)
    elif args.command == "retrieve":
        retrieve_file_from_vault(args.vault_name, args.encrypted_filename, args.output_path)
    elif args.command == "list":
        list_vault_contents(args.vault_name)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
