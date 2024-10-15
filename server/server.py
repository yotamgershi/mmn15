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

    def read_port():
        try:
            with open('port.info', 'r', 'utf-8') as f:
                return int(f.read())
        except FileNotFoundError:
            return utils.DEFAULT_PORT

    def start(self, sock: socket.socket):
        conn = sock.accept()[0]
        conn.setblocking(False)
        client = ClientHandler(conn, self.db)
        self.sel.register(conn, selectors.EVENT_READ, client.handle_request)

    def create_socket(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(Server.MAX_CONNECTIONS)
        sock.setblocking(False)
        self.sel.register(sock, selectors.EVENT_READ, self.start)

    def run(self):
        self.create_socket()
        while self.not_stopped:
            events = self.sel.select()
            for key, mask in events:
                key.data(key.fileobj, mask)

    def stop(self):
        self.not_stopped = False
        self.sel.close()
        if not self.sock:
            self.sock.close()


def main():
    server = Server("localhost")
    server.run()


if __name__ == "__main__":
    main()
