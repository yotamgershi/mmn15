import logging
from typing import Tuple
from uuid import uuid4
from datetime import datetime
from client_responses import Response, ResponseCode
from db_handler import DBHandler
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

AES_KEY_SIZE = 16


class RequestCode:
    SIGN_UP = 825
    SEND_PUBLIC_KEY = 826
    SIGN_IN = 827


class Request:
    CLIENT_ID_SIZE = 16
    VERSION_SIZE = 1
    CODE_SIZE = 2
    PAYLOAD_SIZE_SIZE = 4
    MAX_PAYLOAD_SIZE = 1024

    def __init__(self, data: bytes):
        self.header = Request.parse_header(data)

        self.client_id = self.header[0]
        logging.info(f"Client ID: {self.client_id.hex()}")
        self.version = self.header[1]
        self.code = self.header[2]
        self.payload_size = self.header[3]
        self.payload = self.header[4]

        if self.payload_size > Request.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Invalid request: payload size exceeds maximum size of {Request.MAX_PAYLOAD_SIZE}")
        if len(self.payload) != self.payload_size:
            raise ValueError(f"Invalid request: payload size {self.payload_size} does not match actual size {len(self.payload)}")

    @staticmethod
    def parse_header(data: bytes) -> Tuple[bytes, int, int, int, bytes]:
        if len(data) < Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE:
            raise ValueError("Invalid request: missing header fields")

        client_id = data[:Request.CLIENT_ID_SIZE]
        version = data[Request.CLIENT_ID_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE]
        code = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE]
        payload_size = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE]
        payload = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE:]

        try:
            version = int.from_bytes(version, byteorder='little')
            code = int.from_bytes(code, byteorder='little')
            payload_size = int.from_bytes(payload_size, byteorder='little')
            payload = payload[:payload_size]
        except Exception as e:
            raise ValueError(f"Error parsing header fields: {e}")

        return client_id, version, code, payload_size, payload

    def __str__(self):
        try:
            # Attempt to decode payload as UTF-8 if possible, otherwise show it as hex for binary data
            clean_payload = self.payload.decode('utf-8').replace('\0', '')
        except UnicodeDecodeError:
            clean_payload = self.payload.hex()  # Display binary data as hex

        # Always show the client ID as hex (since it's binary data)
        clean_client_id = self.client_id.hex()  # Display binary data as hex
        return f"Request(client_id={clean_client_id}, version={self.version}, code={self.code}, payload_size={self.payload_size}, payload={clean_payload})"

    def handle_sign_up(self, db_hand: DBHandler) -> Response:
        # logging.info(f"Sign up request received: \n{str(self)}")
        client_name = self.payload.decode('utf-8').replace('\0', '').strip()

        if not db_hand.is_registered(client_name=client_name):
            client_id = uuid4().bytes
            response = Response(code=ResponseCode.SIGN_UP_SUCCESS, payload=client_id)
            db_hand.insert_client(client_id=client_id, name=self.payload, public_key=b'', last_seen=datetime.now(), aes_key=b'')
            return response

        return Response(code=ResponseCode.SIGN_UP_ERROR, payload='Client already registered')

    def __bytes__(self) -> bytes:
        return b''.join(self.header) + self.payload

    # Helper function to handle key generation, encryption, and logging
    @staticmethod
    def handle_keys(client_id: bytes, db_hand: DBHandler) -> Tuple[bytes, bytes]:
        """
        Generate AES key, retrieve public key, and encrypt AES key with the public RSA key.
        Returns the client_id and the encrypted AES key.
        """
        # Retrieve the client's public key from the database
        public_key = db_hand.get_client(client_id)[2]  # Assuming the public key is in the 3rd column
        logging.info(f"Retrieved public key: {public_key.hex()}")

        # Generate a new AES key for the client
        aes_key = Random.get_random_bytes(AES_KEY_SIZE)

        # Encrypt the AES key with the client's public RSA key
        encrypted_aes_key = Request.encrypt_aes_key_with_rsa(aes_key, public_key)

        logging.info(f"Generated new AES key: {aes_key.hex()}")
        return client_id, encrypted_aes_key

    def handle_send_public_key(self, db_hand: DBHandler) -> Response:
        logging.info(f"Send public key request received: client_id={self.client_id.hex()}, payload={self.payload.hex()}")

        client_id = self.client_id  # Keep as binary
        name = self.payload[:255].rstrip(b'\x00').decode('ascii')
        public_key = self.payload[255:415]  # 160 bytes for the public key

        logging.info(f"Extracted name: {name}, public key: {public_key.hex()}")

        # Update the client's public key in the database
        db_hand.set_client_public_key(client_id=client_id, public_key=public_key)

        # Use the helper function to handle AES generation and encryption
        client_id, encrypted_aes_key = Request.handle_keys(client_id, db_hand)

        # Set the AES key in the database after encryption
        db_hand.set_client_aes_key(client_id, encrypted_aes_key)

        # Construct the response payload: 16-byte client ID + encrypted AES key
        response_payload = client_id + encrypted_aes_key

        # Return the response with the encrypted AES key included in the payload
        return Response(code=ResponseCode.RECEIVE_PUBLIC_KEY, payload=response_payload)

    @staticmethod
    def encrypt_aes_key_with_rsa(aes_key: bytes, public_key: bytes) -> bytes:
        try:
            logging.info("Encrypting AES key with RSA...")
            logging.info(f"AES key: {aes_key.hex()}")
            logging.info(f"Public key: {public_key.hex()}")

            # Load the RSA public key from the received payload (DER or PEM)
            rsa_key = RSA.import_key(public_key)

            # Use PKCS1_OAEP for RSA encryption
            cipher_rsa = PKCS1_OAEP.new(rsa_key)

            # Encrypt the AES key using the public key
            encrypted_aes_key = cipher_rsa.encrypt(aes_key)

            return encrypted_aes_key
        except Exception as e:
            logging.error(f"Error during RSA encryption: {e}")
            raise

    def handle_sign_in(self, db_hand: DBHandler) -> Response:
        logging.info(f"Sign in request received: \n{str(self)}")
        client_name = self.payload.decode('utf-8').replace('\0', '').strip()
        logging.info(f"Client name: {client_name}")

        # Check if the client is registered
        client_id_from_db = db_hand.is_registered(client_name=client_name)
        if client_id_from_db is None:
            logging.info(f"Client {client_name} not found.")
            client_id = uuid4().bytes  # Generate a new client ID if not found
            return Response(code=ResponseCode.SIGN_IN_FAILURE, payload=client_id)

        # Use the client ID from the database
        client_id = self.client_id  # This is from the request

        # Check if the client ID matches the one in the database
        if client_id != client_id_from_db:
            logging.info(f"Client ID mismatch: {client_id.hex()} != {client_id_from_db.hex()}, generating new ID.")
            client_id = uuid4().bytes  # Generate a new ID in case of mismatch
            return Response(code=ResponseCode.SIGN_IN_FAILURE, payload=client_id)

        # Update the last seen timestamp for the client
        db_hand.update_last_seen(client_id, datetime.now())

        logging.info(f"Client {client_name} signed in successfully.")

        # Use the helper function to handle AES generation and encryption
        client_id, encrypted_aes_key = Request.handle_keys(client_id, db_hand)

        # Construct the response payload
        payload = client_id + encrypted_aes_key

        return Response(code=ResponseCode.SIGN_IN_SUCCESS, payload=payload)
