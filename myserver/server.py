import socket
import logging
from client_requests import Request, RequestCode
from db_handler import DBHandler

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def get_port_from_file(filename: str = "port.info") -> int:
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return int(f.read())  # Read and convert port number to int
    except FileNotFoundError:
        logging.error(f"File {filename} not found. Using default port 1234.")
        return 1234  # Default port if file not found
    except ValueError:
        logging.error(f"Invalid port number in {filename}. Using default port 1234.")
        return 1234  # Default port if the file content is not a valid number


class Server:
    def __init__(self, filename: str = "port.info"):
        self.host = "localhost"
        self.port = get_port_from_file(filename)
        self.db_handler = DBHandler("defensive.db")
        logging.info(f"Server initialized on {self.host}:{self.port}")

    def start(self):
        try:
            # Create and bind the server socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)  # Set a timeout of 1 second for the socket
                s.bind((self.host, self.port))
                s.listen(1)
                logging.info(f"Server is listening on {self.host}:{self.port}")
                self.accept_connection(s)
        except KeyboardInterrupt:
            logging.info("\nServer shutting down gracefully...")
        except Exception as e:
            logging.error(f"An error occurred: {e}")
        finally:
            logging.info("Server closed.")

    def accept_connection(self, sock: socket.socket):
        while True:
            try:
                conn, addr = sock.accept()
                conn.settimeout(5.0)  # Increased the timeout to 5 seconds
                logging.info(f"Connected by {addr}")
                with conn:
                    while True:
                        try:
                            data = conn.recv(1024)
                            if not data:
                                logging.info("Client disconnected")
                                break
                            logging.info(f"Received: {data}")
                            self.handle_request(data, conn)
                        except socket.timeout:
                            logging.warning("Socket timed out")
                            continue  # Keep waiting for data within the timeout
            except socket.timeout:
                pass  # Continue listening for new connections

    def handle_request(self, data: bytes, conn: socket.socket):
        logging.info("Handling request...")

        request = Request(data)

        match request.code:
            case RequestCode.SIGN_UP:
                logging.info("Received SIGN_UP request")
                response = request.handle_sign_up(self.db_handler)
                conn.sendall(response.to_bytes())
                logging.info(f"Sent response: {response}")
            case RequestCode.SEND_PUBLIC_KEY:
                logging.info("Received SEND_PUBLIC_KEY request")
                response = request.handle_send_public_key(self.db_handler)
                conn.sendall(response.to_bytes())
                logging.info(f"Sent response: {response}")
            case _:
                logging.error(f"Unknown request code: {request.code}")


# Example usage
if __name__ == "__main__":
    localhost = socket.gethostbyname(socket.gethostname())
    server = Server("port.info")
    server.start()
