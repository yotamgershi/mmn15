import selectors
import socket

from database_handler import DataBaseHandler
from client_handler import ClientHandler
import utils


class Server:
    MAX_CONNECTIONS = 100

    def __init__(self, host: str):
        self.port = Server.read_port()
        self.host = host
        self.sel = selectors.DefaultSelector()
        self.not_stopped = True
        self.version = utils.VERSION
        self.db = DataBaseHandler()
        self.sock = None

    @staticmethod
    def read_port():
        try:
            with open('port.info', 'r', encoding='utf-8') as f:
                return int(f.read())
        except FileNotFoundError:
            return utils.DEFAULT_PORT

    def start(self, sock: socket.socket):
        print("Server started")
        try:
            conn, addr = sock.accept()
            conn.setblocking(False)
            client = ClientHandler(conn, self.db)
            self.sel.register(conn, selectors.EVENT_READ, lambda sock: client.handle_request())
        except Exception as e:
            print(f"Error accepting connection: {e}")

    def create_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(Server.MAX_CONNECTIONS)
        self.sock.setblocking(False)
        self.sel.register(self.sock, selectors.EVENT_READ, self.start)
        print(f"Socket created, listening on {self.host}:{self.port}")

    def run(self):
        self.create_socket()
        while self.not_stopped:
            events = self.sel.select()
            for key, mask in events:
                key.data(key.fileobj)

    def stop(self):
        self.not_stopped = False
        self.sel.close()
        if self.sock:
            self.sock.close()


def main():
    server = Server("localhost")
    server.run()


if __name__ == "__main__":
    main()
