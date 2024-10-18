import socket
from client_requests import Request, SignUpRequest, request_codes
from db_handler import DBHandler
from uuid import uuid4

class Server:
    def __init__(self, filename: str):
        self.host = '127.0.0.1'  # Localhost IP
        self.port = self.get_port_from_file(filename)  # Get port from file
        self.db_handler = DBHandler("defensive.db")
        print(f"Server initialized on {self.host}:{self.port}")

    @staticmethod
    def get_port_from_file(filename: str = "port.info") -> int:
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                return int(f.read())  # Read and convert port number to int
        except FileNotFoundError:
            print(f"File {filename} not found. Using default port 1234.")
            return 1234  # Default port if file not found
        except ValueError:
            print(f"Invalid port number in {filename}. Using default port 1234.")
            return 1234  # Default port if the file content is not a valid number

    @staticmethod
    def generate_id() -> bytes:
        return uuid4().bytes

    def start(self):
        try:
            # Create and bind the server socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.0)  # Set a timeout of 1 second for the socket
                s.bind((self.host, self.port))
                s.listen(1)
                print(f"Server is listening on {self.host}:{self.port}")
                self.accept_connection(s)
        except KeyboardInterrupt:
            print("\nServer shutting down gracefully...")
        except Exception as e:
            print(f"An error occurred: {e}")
        finally:
            print("Server closed.")

    def accept_connection(self, sock: socket.socket):
        while True:
            try:
                # Accept a client connection
                conn, addr = sock.accept()
                conn.settimeout(1.0)  # Set a timeout for client communication
                print(f"Connected by {addr}")
                with conn:
                    while True:
                        try:
                            data = conn.recv(1024)
                            if not data:
                                print("Client disconnected")
                                break
                            print(f"Received: {data}")
                            self.handle_request(data, conn)
                        except socket.timeout:
                            pass  # Ignore the timeout and continue checking for data
            except socket.timeout:
                pass  # Ignore the timeout and continue listening for connections

    def handle_request(self, data: bytes, conn: socket.socket):
        print("Handling request...")
        try:
            if len(data) < Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE:
                raise ValueError("Invalid request: missing header fields")

            client_id = data[:Request.CLIENT_ID_SIZE]
            version = data[Request.CLIENT_ID_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE]
            code = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE]
            payload_size = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE]
            payload = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE:]

            version = int.from_bytes(version, byteorder='little')
            code = int.from_bytes(code, byteorder='little')
            payload_size = int.from_bytes(payload_size, byteorder='little')
            print(f"Code is {code}")

            if code == request_codes["SIGN_UP"]:
                return self.handle_request_sign_up(client_id, version, code, payload_size, payload, conn)

        except ValueError as e:
            print(f"Error parsing request: {e}")
            return

    def handle_request_sign_up(self, client_id: bytes, version: bytes, code: bytes, payload_size: bytes, payload: bytes, conn: socket.socket):
        print("Handling sign-up request...")
        try:
            request = SignUpRequest(client_id, version, code, payload_size, payload)
            print(f"Sign-up request received: {request}")
            self.db_handle_sign_up(request)
        except ValueError as e:
            print(f"Error handling sign-up request: {e}")
            return

    def db_handle_sign_up(self, request: SignUpRequest):
        """Handle inserting or checking the client in the database based on the request."""
        client_id = request.client_id
        client_name = request.payload.decode('utf-8').rstrip('\0')  # Decode the payload (name)

        # Assume these values are provided or generated for the new client
        public_key = b'some_public_key_bytes'  # You'd normally get this from the request or generate it
        last_seen = '2024-10-18 12:00:00'  # You'd normally get the current time dynamically
        aes_key = b'some_aes_key_bytes'  # You'd normally generate this securely

        # Check if the client already exists in the database
        existing_client = self.db_handler.get_client(client_id)

        if existing_client:
            print(f"Client already exists: {existing_client}")
        else:
            # Insert the new client into the database
            self.db_handler.insert_client(client_id, client_name, public_key, last_seen, aes_key)
            print(f"New client added to the database: {client_name} ({client_id})")


# Example usage
if __name__ == "__main__":
    localhost = socket.gethostbyname(socket.gethostname())
    server = Server("port.info")
    server.start()
