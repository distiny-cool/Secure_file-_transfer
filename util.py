import base64
from cryptography.fernet import Fernet


def base64Encode(text):
    """Encode the text into base64 format."""
    return base64.b64encode(text.encode("utf-8"))


def base64Decode(text):
    """Decode the text from base64 format."""
    return base64.b64decode(text).decode("utf-8")


def generate_and_save_key(key_path="session.key"):
    """Generates a key and save it into a file"""
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)

def load_key(key_path="session.key"):
    """Loads the key from the current directory named `session.key`"""
    try:
        with open(key_path, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Key not found. Please generate a key first.")
        exit(1)

def encrypt(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and write it"""
    fer = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    # encrypt data
    encrypted_data = fer.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)

def decrypt(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and write it"""
    fer = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = fer.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)

