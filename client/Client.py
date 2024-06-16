from datetime import datetime, timezone
import os
import socket
import threading
import time

from util import *


class Client:
    IP = "127.0.0.1"
    PORT = 2333
    ADDR = (IP, PORT)
    SIZE = 1024
    CLIENT_DATA_PATH = "Client_data"
    CLIENT_CONFIG_PATH = "Client_config"
    FORMAT = "utf-8"

    def __init__(self):
        self.client_directory, self.token = login()
        self.session_key = None  # 会话密钥
        self.sever_public_key = None  # 服务器公钥
        self.client_private_key = None  # 客户端私钥

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(self.ADDR)
        self.condition = threading.Condition()
        self.last_response = None

        if not os.path.exists(self.CLIENT_DATA_PATH):
            os.makedirs(self.CLIENT_DATA_PATH)
        if not os.path.exists(self.CLIENT_CONFIG_PATH):
            os.makedirs(self.CLIENT_CONFIG_PATH)

    def send_command(self, cmd, data=None):  # 命令@明文数据
        """Send commands to the server."""
        with self.condition:
            if data:
                send_data = f"{cmd}@{data}"
            else:
                send_data = cmd
            # enc_data = encrypt_text(send_data, self.token)
            self.client.sendall(b64_encode_text(send_data))
            self.condition.wait()  # Wait for the response before returning

    def send_encrypt_command(self, cmd, data=None):  # 加密数据
        """Send commands to the server."""
        with self.condition:
            if data:
                send_data = f"{cmd}@{data}"
            else:
                send_data = cmd

            # 加密数据
            send_data = encrypt_text(send_data, self.session_key.encode()).decode(
                "utf-8"
            )
            # print(f"send_data: {send_data}")
            self.client.sendall(b64_encode_text(send_data))
            self.condition.wait()  # Wait for the response before returning

    def upload_file(self, path):
        """Handle the upload file logic."""
        try:
            with open(path, "rb") as file:
                file_contents = file.read()
        except FileNotFoundError:
            print(f"ERROR: File '{path}' not found.")
            return
        filename = path.split("/")[-1]  # for UNIX-like paths
        filename = path.split("\\")[-1]  # for Windows paths

        # Encode the filename and file contents(Escape special characters)
        b64_filename = b64_encode_text(filename).decode(self.FORMAT)

        b64_contents = b64_encode_file(file_contents).decode(self.FORMAT)
        b64_contents = encrypt_text(b64_contents, self.session_key.encode()).decode(
            self.FORMAT
        )
        # print(f"b64_contents: {b64_contents}")

        b64_hash = calculate_hash(b64_contents, self.session_key.encode(), self.FORMAT)
        # print(f"hash: {b64_hash}")

        data = f"UPLOAD@{b64_filename}@{b64_contents}@{b64_hash}$"
        self.send_command(data)

    def change_key(self) -> bool:
        """Change the session key."""
        # 首先，服务器主动发送"OK"信息，并获取明文的服务器公钥
        data = b64_decode_text(self.client.recv(self.SIZE))
        cmd = data.split("@")[0]
        if cmd != "OK":
            print(f"ERROR: Expected CA command, but got {cmd}.")
            return False
        msg, filename, contents = (
            data.split("@")[1],
            data.split("@")[2],
            data.split("@")[3],
        )
        print(f"[SERVER]: {msg}")

        self.sever_public_key = b64_decode_text(contents)
        # print(type(self.sever_public_key))
        key_fingerprint = generate_public_key_fingerprint(self.sever_public_key)
        print(f"[SERVER]: The server public key fingerprint is: {key_fingerprint}")
        print(
            f"[SERVER]: Please confirm whether the server fingerprint is correct. If it is correct, press YES. "
            f"Otherwise, press NO."
        )

        success = True
        # 若接收服务器公钥，则通过“YES”发送加密后的对话密钥，若不通过，通过“NO”关闭连接
        data = b64_decode_text(self.client.recv(self.SIZE))
        # print(data)
        with self.condition:
            self.condition.notify()  # Notify waiting thread
        if data:
            cmd, _, msg = data.partition("@")
            if cmd == "BYE":
                print(f"[SERVER]: {msg}")
                success = False
            elif cmd == "SUCCESS":
                print(f"[SERVER]: Identity authentication passed, please continue")
        return success

    def receive_messages(self):
        """Receive messages from the server and handle them."""
        try:
            success = self.change_key()
            # 在这之后都是对称密钥机密的通信

            while success:
                data = b64_decode_text(self.client.recv(self.SIZE))
                if data:
                    cmd, _, msg = data.partition("@")
                    with self.condition:
                        self.last_response = (cmd, msg)
                        self.condition.notify()  # Notify waiting thread
                    if cmd == "BYE":
                        print(f"[SERVER]: {msg}")
                        break
                    elif cmd == "FILE":
                        msgs = msg.split("@")
                        filename = msgs[0]
                        filename = b64_decode_text(filename)
                        # print(filename)
                        # print(self.client_directory)
                        filepath = os.path.join(self.client_directory, filename)

                        # Receive the file content all
                        # todo: if spent too much time, it should be break and return error
                        contents = (
                            msgs[1] if len(msgs) == 2 else msgs[1] + "@" + msgs[2]
                        )
                        while not contents.endswith("$"):
                            contents += b64_decode_text(self.client.recv(self.SIZE))
                        contents = contents[:-1]

                        split_hash = contents.split("@")
                        file_contents = split_hash[0]
                        file_hash_expected = split_hash[1]

                        ## TEST SAMPLE FOR INTEGRITY CHECK
                        # with open('test1.txt', "rb") as f:
                        #     file_contents = f.read()
                        # file_contents = b64_encode_file(file_contents).decode(self.FORMAT)
                        # file_contents = encrypt_text(file_contents, self.session_key.encode()).decode(
                        #     "utf-8"
                        # )

                        # print("file_contents: ", file_contents)
                        # print("file_hash_expected", file_hash_expected)

                        if verify_file_integrity(
                            file_contents,
                            file_hash_expected,
                            self.session_key.encode(),
                            self.FORMAT,
                        ):
                            contents = decrypt_text(
                                file_contents.encode(self.FORMAT), self.session_key
                            )
                            contents = b64_decode_file(contents.encode("utf-8"))

                            with open(filepath, "wb") as file:
                                file.write(contents)
                            print(f"File '{filename}' downloaded successfully.")
                        else:
                            print(
                                f"File '{filename}' downloaded failed: integrity check failed"
                            )
                    elif cmd == "OK":
                        print(msg)
                    elif cmd == "ERROR":
                        print(f"ERROR: {msg}")
        finally:
            print("receive_messages: Disconnected from the server.")
            self.client.close()

    def send_commands(self):
        """Handle user input and send commands to the server."""
        time.sleep(0.1)
        try:
            while True:
                data = input("> ")
                data = data.split(" ")
                cmd = data[0]

                if cmd in {"HELP", "LIST", "LOGOUT"}:
                    self.send_command(cmd)
                    if cmd == "LOGOUT":
                        break

                elif cmd == "DELETE":
                    if len(data) > 1:
                        filename = data[1]
                        filename_encoded = b64_encode_text(filename).decode(self.FORMAT)
                        self.send_command(cmd, filename_encoded)
                    else:
                        print("ERROR: No filename provided for DELETE.")

                elif cmd == "UPLOAD":
                    if len(data) > 1:
                        path = data[1]
                        self.upload_file(path)
                    else:
                        print("ERROR: No path provided for UPLOAD.")

                elif cmd == "DOWNLOAD":
                    if len(data) > 1:
                        filename = data[1]
                        filename_encoded = b64_encode_text(filename).decode(self.FORMAT)
                        self.send_command(cmd, filename_encoded)
                    else:
                        print("ERROR: No filename provided for DOWNLOAD.")

                elif cmd == "YES":
                    self.session_key = (
                        generate_session_key().decode()
                    )  # 生成会话密钥，并将密钥转换为字符串
                    encrypt_session_key = encrypt_rsa(
                        self.sever_public_key, self.session_key
                    )
                    # print(encrypt_session_key, type(encrypt_session_key))
                    send_data = f"{cmd}@{encrypt_session_key}@{self.token}"
                    # print(send_data)
                    self.client.sendall(b64_encode_text(send_data))
                    # print(f"Session key and token sent successfully!")
                    with self.condition:
                        self.condition.wait()  # Wait for the response before returning
                    time.sleep(0.1)

                elif cmd == "NO":
                    print(
                        "[CLIENT]: The connection will be closed because you rejected the server's public key fingerprint."
                    )
                    # 发送NO命令，关闭连接
                    send_data = f"{cmd}@$"
                    self.client.sendall(b64_encode_text(send_data))
                    with self.condition:
                        self.condition.wait()  # Wait for the response before returning
                    break
                else:
                    print("Invalid command. Type HELP for more information.")
        finally:
            print("send_commands: Disconnected from the server.")
            self.client.close()


def login():
    # 如果登录成功，获得证明用户身份的token
    # 登录, 用户本地存储了在此登录过得用户的公钥、密码加密的私钥
    # 如果用户输入的用户名不存在，则为用户创建一个新的账户（新的私钥）
    # 如果用户输入的用户名存在，且密码正确。则说明本地的私钥属于当前操作的用户
    print("[CLIENT]: Welcome to the File Transfer System!")
    print("[CLIENT]: Please enter your username and password to login.")
    print(
        "[CLIENT]: If the username does not exist, a new account will be created for you."
    )

    while True:
        username = input("[Username]: ")
        password = input("[Password]: ")

        hash_name = hash_str(username)
        hash_password = hash_str(password)

        user_path = "Client_config" + "/" + hash_name
        if not os.path.exists(user_path):
            os.makedirs(user_path)
            print("[CLIENT]: User does not exist, register for you.")
            generate_rsa_key_pair_with_password(user_path, hash_password)
            break
        else:
            print(f"[CLIENT]: User {username} already exists.")
            if verify_rsa_private_key_with_password(user_path, hash_password):
                print("[CLIENT]: The password is correct, please continue.")
                break
            else:
                print("[CLIENT]: The password is incorrect.")
                continue_or_exit = input(
                    "[CLIENT]: To exit, please enter [exit]. To continue, please enter any character: "
                )
                if continue_or_exit == "exit":
                    exit(0)

    # 获取当前时间戳，以分钟为单位
    timestamp = int(datetime.now(timezone.utc).timestamp() // 600)
    # 在消息末尾附加时间戳
    message_with_timestamp = str(timestamp)
    print("[CLIENT]: The message to be signed is:", message_with_timestamp)
    private_key_path = os.path.join(user_path, "private.pem")
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=hash_password.encode(), backend=default_backend()
        )

    signature = sign_message_with_private_key(private_key, message_with_timestamp)

    public_key_data = getCASendData(
        os.path.join(user_path, "public.pem")
    )  # send_data = f"{b64_filename}@{b64_contents}$"
    # print(f"{signature}@{public_key_data}")

    client_directory = os.path.join("Client_data", username)
    if not os.path.exists(client_directory):
        os.makedirs(client_directory)
    # print("client_directory: ", client_directory)
    return client_directory, f"{signature}@{public_key_data}"


if __name__ == "__main__":

    client = Client()
    # print(f"client_directory: {client.client_directory}")
    receive_thread = threading.Thread(target=client.receive_messages)
    send_thread = threading.Thread(target=client.send_commands)

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()
