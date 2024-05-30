import os
import socket
import threading
import time

from util import *


class Client:
    IP = '127.0.0.1'
    PORT = 2333
    ADDR = (IP, PORT)
    SIZE = 1024
    CLIENT_DATA_PATH = "Client_data"
    CLIENT_CONFIG_PATH = "Client_config"
    FORMAT = 'utf-8'

    def __init__(self):
        self.session_key = None
        self.sever_public_key = None

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(self.ADDR)
        self.condition = threading.Condition()
        self.last_response = None
        self.token = None
        if not os.path.exists(self.CLIENT_DATA_PATH):
            os.makedirs(self.CLIENT_DATA_PATH)
        if not os.path.exists(self.CLIENT_CONFIG_PATH):
            os.makedirs(self.CLIENT_CONFIG_PATH)

    def send_command(self, cmd, data=None):
        """Send commands to the server."""
        with self.condition:
            if data:
                send_data = f"{cmd}@{data}"
            else:
                send_data = cmd
            # enc_data = encrypt_text(send_data, self.token)
            self.client.sendall(b64_encode_text(send_data))
            self.condition.wait()  # Wait for the response before returning

    def send_rsa_encrypted_command(self, cmd, data):
        with self.condition:
            if data:
                send_data = f"{cmd}@{data}"
            else:
                send_data = cmd
            encrypt_session_key = encrypt_rsa(self.sever_public_key, send_data)
            self.client.sendall(encrypt_session_key)
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

        self.send_command("UPLOAD", f"{b64_filename}@{b64_contents}$")

    def change_key(self):
        """Change the session key."""
        # 获取服务器公钥
        data = b64_decode_text(self.client.recv(self.SIZE))
        cmd = data.split("@")[0]
        if cmd != "OK":
            print(f"ERROR: Expected CA command, but got {cmd}.")
            return
        msg, filename, contents = data.split("@")[1], data.split("@")[2], data.split("@")[3]
        print(f"[SERVER]: {msg}")

        self.sever_public_key = b64_decode_text(contents)
        print(type(self.sever_public_key))
        key_fingerprint = generate_public_key_fingerprint(self.sever_public_key)
        print(f"服务器公钥指纹为: {key_fingerprint}")
        print("请确认该服务器指纹是否正确，若正确请按YES，否则按NO")

        success = True
        data = b64_decode_text(self.client.recv(self.SIZE))
        with self.condition:
            self.last_response = (cmd, msg)
            self.condition.notify()  # Notify waiting thread
        if data:
            cmd, _, msg = data.partition("@")
            if cmd == "BYE":
                print(f"[SERVER]: {msg}")
                success = False
            elif cmd == "SUCCESS":
                print(f"[SERVER]: 会话密钥交换成功，会话继续！")
        return success

    def receive_messages(self):
        """Receive messages from the server and handle them."""
        try:
            success = self.change_key()
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
                        filename, contents = msg.split("@")
                        filename = b64_decode_text(filename)
                        filepath = f"{self.CLIENT_DATA_PATH}/{filename}"

                        # Receive the file content all
                        # todo: if spent too much time, it should be break and return error
                        while not contents.endswith("$"):
                            contents += b64_decode_text(self.client.recv(self.SIZE))
                        contents = b64_decode_file(contents[:-1])

                        with open(filepath, "wb") as file:
                            file.write(contents)
                        print(f"File '{filename}' downloaded successfully.")
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
                    self.session_key = generate_session_key().decode()  # 生成会话密钥，并将密钥转换为字符串
                    self.send_rsa_encrypted_command(cmd, self.session_key)
                    print(f"会话密钥为: {self.session_key}")

                elif cmd == "NO":
                    print("服务器指纹不正确，连接已断开")
                    self.send_rsa_encrypted_command(cmd, None)

                    break
                else:
                    print("Invalid command. Type HELP for more information.")
        finally:
            print("send_commands: Disconnected from the server.")
            self.client.close()


if __name__ == "__main__":
    client = Client()
    receive_thread = threading.Thread(target=client.receive_messages)
    send_thread = threading.Thread(target=client.send_commands)

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()
