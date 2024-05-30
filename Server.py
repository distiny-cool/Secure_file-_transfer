import os
import socket
import threading
from util import *

class Server:
    IP = "127.0.0.1"
    PORT = 2333
    ADDR = (IP, PORT)
    SIZE = 1024
    SERVER_DATA_PATH = "Server_data"
    SERVER_CONFIG_PATH = "Server_config"
    FORMAT = "utf-8"

    def __init__(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind(self.ADDR)
        self.server.listen()
        if not os.path.exists(self.SERVER_DATA_PATH):
            os.makedirs(self.SERVER_DATA_PATH)
        if not os.path.exists(self.SERVER_CONFIG_PATH):
            os.makedirs(self.SERVER_CONFIG_PATH)
        print("[STARTING] Server is starting.")
        print(f"[LISTENING] Server is listening on {self.IP}:{self.PORT}.")

    def handle_client(self, conn, addr):
        """Handles individual client connection."""
        print(f"[NEW CONNECTION] {addr} connected.")
        conn.send(b64_encode_text("OK@Welcome to the File Server."))

        while True:
            data = b64_decode_text(conn.recv(self.SIZE))
            if not data:
                break
            data = data.split("@")
            cmd = data[0]
            print(f"[{addr}] {cmd}")

            if cmd == "LIST":
                self.handle_list(conn)
            elif cmd == "UPLOAD":
                self.handle_upload(conn, data)
            elif cmd == "DOWNLOAD":
                self.handle_download(conn, data)
            elif cmd == "DELETE":
                self.handle_delete(conn, data)
            elif cmd == "LOGOUT":
                self.handle_logout(conn)
                break
            elif cmd == "HELP":
                self.handle_help(conn)

        print(f"[DISCONNECTED] {addr} disconnected")
        print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 2}")
        conn.close()

    def handle_list(self, conn):
        """Handle listing files on the server."""
        files = os.listdir(self.SERVER_DATA_PATH)
        send_data = "OK@"

        if len(files) == 0:
            send_data += "The server directory is empty"
        else:
            send_data += "\n".join(f for f in files)
        conn.send(b64_encode_text(send_data))

    def handle_upload(self, conn, data):
        """Handle uploading files to the server."""
        file_name = b64_decode_text(data[1])
        file_contents = data[2]
        while not file_contents.endswith("$"):
            file_contents += b64_decode_text(conn.recv(self.SIZE))
        file_contents = b64_decode_file(file_contents[:-1])

        filepath = os.path.join(self.SERVER_DATA_PATH, file_name)
        with open(filepath, "wb") as f:
            f.write(file_contents)
        send_data = "OK@File uploaded successfully."
        conn.send(b64_encode_text(send_data))
    
    def handle_download(self, conn, data):
        """Handle downloading files from the server."""
        files = os.listdir(self.SERVER_DATA_PATH)
        filename = b64_decode_text(data[1])
        if filename not in files:
            conn.send(b64_encode_text("ERROR@File not found."))
            return
        
        filepath = os.path.join(self.SERVER_DATA_PATH, filename)
        with open(filepath, "rb") as f:
            file_contents = f.read()
        b64_filename = b64_encode_text(filename).decode(self.FORMAT)
        b64_contents = b64_encode_file(file_contents).decode(self.FORMAT)

        send_data = "FILE@"
        send_data += f"{b64_filename}@{b64_contents}$"
        conn.send(b64_encode_text(send_data))

    def handle_delete(self, conn, data):
        """Handle deleting files from the server."""
        files = os.listdir(self.SERVER_DATA_PATH)
        send_data = "OK@"
        filename = b64_decode_text(data[1])

        if filename in files:
            os.remove(os.path.join(self.SERVER_DATA_PATH, filename))
            send_data += "File deleted successfully."
        else:
            send_data += "File not found."
        conn.send(b64_encode_text(send_data))
    
    def handle_logout(self, conn):
        """Handle client logout."""
        conn.send(b64_encode_text("BYE@Goodbye!"))
        conn.close()

    def handle_help(self, conn):
        """Send help information to the client."""
        data = "OK@"
        data += "LIST: List all the files from the server.\n"
        data += "UPLOAD <path>: Upload a file to the server.\n"
        data += "DOWNLOAD <filename>: Download a file from the server.\n"
        data += "DELETE <filename>: Delete a file from the server.\n"
        data += "LOGOUT: Disconnect from the server.\n"
        data += "HELP: List all the commands."
        conn.send(b64_encode_text(data))

    def run(self):
        """Run the server and accept connections."""
        while True:
            conn, addr = self.server.accept()
            thread = threading.Thread(target=self.handle_client, args=(conn, addr))
            thread.start()
            print(f"[ACTIVE CONNECTIONS] {threading.active_count() - 1}")

if __name__ == "__main__":
    server = Server()
    server.run()
