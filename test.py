import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def generate_rsa_key_pair_with_password(save_path, password):
    # 生成私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # 将私钥序列化并加密
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    # 保存加密的私钥
    private_key_path = os.path.join(save_path, 'private.pem')
    with open(private_key_path, 'wb') as f:
        f.write(pem)

    # 生成公钥
    public_key = private_key.public_key()

    # 将公钥序列化
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 保存公钥
    public_key_path = os.path.join(save_path, 'public.pem')
    with open(public_key_path, 'wb') as f:
        f.write(pem)

    return private_key_path, public_key_path


def verify_rsa_private_key_with_password(private_key_path, password):
    try:
        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode(),
                backend=default_backend()
            )
        return private_key
    except (ValueError, TypeError) as e:
        # ValueError is raised if the password is incorrect or the key is invalid
        # TypeError is raised if the key file is not in the correct format
        print(f"Failed to decrypt the private key: {e}")
        return None


def sign_message_with_private_key(private_key, message):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # 将签名转换为Base64编码字符串
    return base64.b64encode(signature).decode()


# -*- coding: utf-8 -*-
# @Time     : 2024/6/15 17:04
# @Author   : Daichuan

def main():
    # 示例用法
    save_path = os.path.abspath("Client_config")
    password = "your_password"
    message = "This is a message to sign"

    # 生成RSA密钥对
    private_key_path, public_key_path = generate_rsa_key_pair_with_password(save_path, password)

    # 验证并读取私钥
    private_key = verify_rsa_private_key_with_password(private_key_path, password)
    if private_key:
        print("The password is correct, and the private key is valid.")
        # 使用私钥签名消息
        signature = sign_message_with_private_key(private_key, message)
        print("Signature:", signature)
    else:
        print("The password is incorrect, or the private key is invalid.")


if __name__ == '__main__':
    main()
