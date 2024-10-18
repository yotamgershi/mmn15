import socket
from server import Server


def main():
    localhost = socket.gethostbyname(socket.gethostname())
    my_server = Server(localhost)
    my_server.start()


if __name__ == "__main__":
    main()
