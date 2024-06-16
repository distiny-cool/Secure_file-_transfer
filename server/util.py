import base64
import os

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes


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
    if isinstance(public_key, str):
        public_key = serialization.load_pem_public_key(public_key.encode("utf-8"))

    # 加密数据
    encrypted_data = public_key.encrypt(
        data.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # 将加密结果转换为Base64编码的字符串
    encrypted_data_base64 = base64.b64encode(encrypted_data).decode("utf-8")

    return encrypted_data_base64


def decrypt_rsa(private_key, encrypted_data):
    """Decrypt data (str) from encrypted data(byte) using RSA private key."""
    return private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
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
        public_key_pem.encode("utf-8"), backend=default_backend()
    )

    # 转换为DER格式的字节序列
    public_key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # 计算SHA-256指纹
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(public_key_der)
    sha256_fingerprint = digest.finalize().hex()

    return sha256_fingerprint


def generate_session_key() -> bytes:
    """Generates a key and save it into a file"""
    key = Fernet.generate_key()
    return key


def check_and_generate_keys(directory):
    private_key_path = os.path.join(directory, "private.pem")
    public_key_path = os.path.join(directory, "public.pem")

    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        print("RSA keys not found. Generating new keys...")
        generate_rsa_key_pair(directory)
    else:
        print("RSA keys already exist.")


def getCASendData(filepath):
    # 发送服务器公钥
    with open(filepath, "rb") as f:
        file_contents = f.read()

    b64_filename = b64_encode_text("pubic_key").decode("utf-8")
    b64_contents = b64_encode_file(file_contents).decode("utf-8")

    # salt = os.urandom(16)
    # salt = str(salt)
    # b64_salt = b64_encode_file(salt).decode("utf-8")

    send_data = f"{b64_filename}@{b64_contents}$"
    return send_data


def hash_str(data: str) -> str:
    # 创建一个hash对象
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    # 提供数据给hash对象
    digest.update(data.encode("utf-8"))
    # 获取最终的哈希值
    hash_value = digest.finalize()
    # 将哈希值转换为十六进制字符串表示
    hex_hash_value = hash_value.hex()

    # print(hex_hash_value, "  ", type(hex_hash_value))  # 打印哈希值
    return hex_hash_value


def generate_rsa_key_pair_with_password(save_path, password):
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # 将私钥序列化并加密
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode()),
    )

    # 保存加密的私钥
    private_key_path = os.path.join(save_path, "private.pem")
    with open(private_key_path, "wb") as f:
        f.write(pem)

    # 生成公钥
    public_key = private_key.public_key()

    # 将公钥序列化
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # 保存公钥
    public_key_path = os.path.join(save_path, "public.pem")
    with open(public_key_path, "wb") as f:
        f.write(pem)

    return private_key_path, public_key_path


def verify_rsa_private_key_with_password(user_path, password):
    try:
        private_key_path = os.path.join(user_path, "private.pem")
        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=password.encode(), backend=default_backend()
            )
        return True
    except (ValueError, TypeError) as e:
        # ValueError is raised if the password is incorrect or the key is invalid
        # TypeError is raised if the key file is not in the correct format
        print(f"Failed to decrypt the private key: {e}")
        return False


def sign_message_with_private_key(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    # 将签名转换为Base64编码字符串
    # print("signature", signature)
    return base64.b64encode(signature).decode("utf-8")


# 验证签名
def verify_signature(public_key_pem, message, signature):
    # 加载PEM格式公钥
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode("utf-8"), backend=default_backend()
    )

    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False


# AES加密函数
def encrypt_aes(key, plaintext):
    # 使用PKCS7填充
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    # 创建AES加密器
    iv = os.urandom(16)  # 16 bytes for AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # 加密数据
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv + ciphertext


def calculate_hash(contents, key, format="utf-8", algorithm=hashes.SHA256()):
    # HAMC 计算文件哈希，并进行base64编码
    hasher = hmac.HMAC(key, algorithm)
    hasher.update(contents.encode(format))
    b64_hash = b64_encode_text(hasher.finalize().hex())
    return b64_hash.decode(format)


def verify_file_integrity(contents, expected_hash, key, format="utf-8"):
    # 重新计算哈希，进行完整性检验
    b64_hash = calculate_hash(contents, key, format)
    return b64_hash == expected_hash
