import os
import socket
import base64
import threading
from util import *

class Client:
    IP = '127.0.0.1'
    PORT = 2333
    ADDR = (IP, PORT)
    SIZE = 1024
    CLIENT_DATA_PATH = "Client_data"
    FORMAT = 'utf-8'

    def __init__(self):
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect(self.ADDR)
        self.condition = threading.Condition()
        self.last_response = None
        self.token = None
        if not os.path.exists(self.CLINET_DATA_PATH):
            os.makedirs(self.CLINET_DATA_PATH)

    def send_command(self, cmd, data=None):
        """Send commands to the server."""
        with self.condition:
            if data:
                send_data = f"{cmd}@{data}"
            else:
                send_data = cmd
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

        self.send_command("UPLOAD", f"{b64_filename}@{b64_contents}$")

    def receive_messages(self):
        """Receive messages from the server and handle them."""
        try:
            while True:
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

                        with open(filepath , "wb") as file:
                            file.write(contents)
                        print(f"File '{filename}' downloaded successfully.")
                    elif cmd == "OK":
                        print(msg)
                    elif cmd == "ERROR":
                        print(f"ERROR: {msg}")
        finally:
            print("Disconnected from the server.")
            self.client.close()

    def send_commands(self):
        """Handle user input and send commands to the server."""
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

                else:
                    print("Invalid command. Type HELP for more information.")
        finally:
            self.client.close()

if __name__ == "__main__":
    client = Client()
    receive_thread = threading.Thread(target=client.receive_messages)
    send_thread = threading.Thread(target=client.send_commands)

    receive_thread.start()
    send_thread.start()

    receive_thread.join()
    send_thread.join()
