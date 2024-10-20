import logging
from typing import Tuple
from uuid import uuid4
from datetime import datetime
from client_responses import Response, ResponseCode
from db_handler import DBHandler
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


class RequestCode:
    SIGN_UP = 825
    SEND_PUBLIC_KEY = 826


class Request:
    CLIENT_ID_SIZE = 16
    VERSION_SIZE = 1
    CODE_SIZE = 2
    PAYLOAD_SIZE_SIZE = 4
    MAX_PAYLOAD_SIZE = 1024

    def __init__(self, data: bytes):
        self.header = Request.parse_header(data)

        self.client_id = self.header[0]
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

        clean_client_id = self.client_id.decode('utf-8').replace('\0', '')
        return f"Request(client_id={clean_client_id}, version={self.version}, code={self.code}, payload_size={self.payload_size}, payload={clean_payload})"

    def handle_sign_up(self, db_hand: DBHandler) -> Response:
        logging.info(f"Sign up request received: \n{str(self)}")
        client_name = self.payload.decode('utf-8').replace('\0', '').strip()

        if not db_hand.is_registered(client_name=client_name):
            client_id = uuid4().bytes
            response = Response(code=ResponseCode.SIGN_UP_SUCCESS, payload=client_id)
            db_hand.insert_client(client_id=client_id, name=self.payload, public_key=b'', last_seen=datetime.now(), aes_key=b'')
            return response

        return Response(code=ResponseCode.SIGN_UP_ERROR, payload='Client already registered')

    def __bytes__(self) -> bytes:
        return b''.join(self.header) + self.payload

    def handle_send_public_key(self, db_hand: DBHandler) -> Response:
        logging.info(f"Send public key request received: client_id={self.client_id}, payload={self.payload.hex()}")

        client_id = self.client_id  # Keep as binary
        name = self.payload[:255].rstrip(b'\x00').decode('ascii')
        public_key = self.payload[255:415]  # 160 bytes for the public key

        logging.info(f"Extracted name: {name}, public key: {public_key.hex()}")

        # Update the public key (binary) in the database
        db_hand.update_public_key(client_id, public_key)

        # Retrieve the AES key for the client from the database
        aes_key = db_hand.get_aes_key(client_id)

        # Encrypt the AES key with the client's public RSA key
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

        # Construct the payload: 16-byte client ID + encrypted AES key
        response_payload = client_id + encrypted_aes_key

        # Return a response with the encrypted AES key included in the payload
        return Response(code=ResponseCode.RECEIVE_PUBLIC_KEY, payload=response_payload)


def encrypt_aes_key_with_rsa(aes_key: bytes, public_key: bytes) -> bytes:
    try:
        logging.info("Encrypting AES key with RSA...")
        logging.info(f"AES key: {aes_key.hex()}")
        logging.info(f"Public key: {public_key.hex()}")

        # Load the RSA public key from the received payload (DER or PEM)
        rsa_key = RSA.import_key(public_key)

        # Use PKCS1_OAEP for RSA encryption
        logging.info(f"Encrypting AES key with RSA public key: {rsa_key}")
        cipher_rsa = PKCS1_OAEP.new(rsa_key)

        # Encrypt the AES key using the public key
        logging.info(f"Encrypting AES key: {aes_key.hex()}")
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        return encrypted_aes_key
    except Exception as e:
        logging.error(f"Error during RSA encryption: {e}")
        raise

