import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def b64_encode_text(text):
    """Encode the text(str) into bytes with base64 format."""
    return base64.b64encode(text.encode("utf-8"))


def b64_decode_text(text):
    """Decode the text(bytes/str) from base64 format into str."""
    return base64.b64decode(text).decode("utf-8")

def b64_encode_file(file):
    """Encode the file into bytes with base64 format."""
    return base64.b64encode(file)

def b64_decode_file(file):
    """Decode the file from base64 format into bytes."""
    return base64.b64decode(file)

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


def encrypt_file(filename, key):
    """Given a filename (str) and key (bytes), it encrypts the file and write it"""
    fer = Fernet(key)
    with open(filename, "rb") as file:
        file_data = file.read()
    # encrypt data
    encrypted_data = fer.encrypt(file_data)
    with open(filename, "wb") as file:
        file.write(encrypted_data)


def decrypt_file(filename, key):
    """Given a filename (str) and key (bytes), it decrypts the file and write it"""
    fer = Fernet(key)
    with open(filename, "rb") as file:
        encrypted_data = file.read()
    # decrypt data
    decrypted_data = fer.decrypt(encrypted_data)
    with open(filename, "wb") as file:
        file.write(decrypted_data)

def encrypt_text(text, key):
    """Given a text (str) and key (bytes), it encrypts the text and return it"""
    fer = Fernet(key)
    return fer.encrypt(text.encode("utf-8"))

def decrypt_text(text, key):
    """Given a text (str) and key (bytes), it decrypts the text and return it"""
    fer = Fernet(key)
    return fer.decrypt(text).decode("utf-8")


def generate_rsa_key_pair(save_path):
    """Generate RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    try:
        # Save private key
        with open(f"{save_path}/private.pem", "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Save public key
        with open(f"{save_path}/public.pem", "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
    except Exception as e:
        print(f"Error: {e}")


def load_public_key(path):
    """Load public key from the given path."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def load_private_key(path):
    """Load private key from the given path."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)
    

def encrypt_rsa(public_key, data):
    if type(public_key) == str:
        public_key = serialization.load_pem_public_key(public_key.encode('utf-8'))
    """Encrypt data (str) using RSA public key as encrypted data(byte).."""
    return public_key.encrypt(
        data.encode("utf-8"), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_rsa(private_key, encrypted_data):
    """Decrypt data (str) from encrypted data(byte) using RSA private key."""
    return private_key.decrypt(
        encrypted_data, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode("utf-8")


def generate_public_key_fingerprint(public_key_pem):
    """
    生成公钥的SHA-256指纹

    参数:
    public_key_pem (str): 公钥的PEM格式字符串

    返回:
    str: 公钥的SHA-256指纹
    """
    # 加载PEM格式公钥
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )

    # 转换为DER格式的字节序列
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 计算SHA-256指纹
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key_der)
    sha256_fingerprint = digest.finalize().hex()

    return sha256_fingerprint

def generate_session_key():
    """Generates a key and save it into a file"""
    key = Fernet.generate_key()
    return key



def check_and_generate_keys(directory):
    private_key_path = os.path.join(directory, 'private.pem')
    public_key_path = os.path.join(directory, 'public.pem')

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("RSA keys not found. Generating new keys...")
        generate_rsa_key_pair(directory)
    else:
        print("RSA keys already exist.")


def getCASendData(filepath):
    # 发送服务器公钥
    with open(filepath, "rb") as f:
        file_contents = f.read()

    b64_filename = b64_encode_text(filepath).decode("utf-8")
    b64_contents = b64_encode_file(file_contents).decode("utf-8")

    # salt = os.urandom(16)
    # salt = str(salt)
    # b64_salt = b64_encode_file(salt).decode("utf-8")

    send_data = f"{b64_filename}@{b64_contents}$"
    return send_data



if __name__ == "__main__":
    generate_rsa_key_pair(
        "C:\\Users\\kody\\Desktop\\Secure_file _transfer\\Server_config"
    )
    print("[+] Keys generated successfully.")
    public_key = load_public_key(
        "C:\\Users\\kody\\Desktop\\Secure_file _transfer\\Server_config\\public.pem"
    )
    print("[+] Public key loaded successfully.")
    encrypted_data = encrypt_rsa(public_key, "Hello, World!")
    private_key = load_private_key(
        "C:\\Users\\kody\\Desktop\\Secure_file _transfer\\Server_config\\private.pem"
    )
    print("[+] Private key loaded successfully.")
    plaintext = decrypt_rsa(private_key, encrypted_data)
    print("[+] Decrypted data:", plaintext)
