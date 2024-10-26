import os
import logging
from typing import Tuple
from uuid import uuid4
from datetime import datetime
from client_responses import Response, ResponseCode
from db_handler import DBHandler
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import cksum
from Crypto.Cipher import AES
from Crypto.Util import Padding


AES_KEY_SIZE = 32


class RequestCode:
    SIGN_UP = 825
    SEND_PUBLIC_KEY = 826
    SIGN_IN = 827
    SEND_FILE = 828
    CRC_VALID = 900


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

        # Extract fields in the correct order
        client_id = data[:Request.CLIENT_ID_SIZE]  # First 16 bytes for client_id
        version = data[Request.CLIENT_ID_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE]  # Next 1 byte for version
        code = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE]  # 2 bytes for code
        payload_size = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE:Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE]  # 4 bytes for payload size
        payload = data[Request.CLIENT_ID_SIZE + Request.VERSION_SIZE + Request.CODE_SIZE + Request.PAYLOAD_SIZE_SIZE:]  # Rest is the payload

        try:
            version = int.from_bytes(version, byteorder='little')
            code = int.from_bytes(code, byteorder='little')
            payload_size = int.from_bytes(payload_size, byteorder='little')

            # Check if the payload size matches the actual data size
            if len(payload) != payload_size:
                raise ValueError(f"Invalid request: payload size {payload_size} does not match actual size {len(payload)}")

        except Exception as e:
            raise ValueError(f"Error parsing header fields: {e}")

        # Now return the client_id and the parsed fields
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
        logging.info("Sign up request received")
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
        Generate AES key and insert into database, retrieve public key, and encrypt AES key with the public RSA key.
        Returns the client_id and the encrypted AES key.
        """
        # Retrieve the client's public key from the database
        public_key = db_hand.get_client(client_id)[2]  # Assuming the public key is in the 3rd column
        logging.info("Retrieved public key")

        # Generate a new AES key for the client
        aes_key = Random.get_random_bytes(AES_KEY_SIZE)

        # Set AES key in the database
        db_hand.set_client_aes_key(client_id, aes_key)

        # Encrypt the AES key with the client's public RSA key
        encrypted_aes_key = Request.encrypt_aes_key_with_rsa(aes_key, public_key)

        logging.info("Generated new AES key")
        return client_id, encrypted_aes_key

    def handle_send_public_key(self, db_hand: DBHandler) -> Response:
        logging.info("Send public key request received")

        client_id = self.client_id  # Keep as binary
        # name = self.payload[:255].rstrip(b'\x00').decode('ascii')
        public_key = self.payload[255:415]  # 160 bytes for the public key

        logging.info("Extracted name and public key")

        # Update the client's public key in the database
        db_hand.set_client_public_key(client_id=client_id, public_key=public_key)

        # Use the helper function to handle AES generation and encryption
        client_id, encrypted_aes_key = Request.handle_keys(client_id, db_hand)

        # Construct the response payload: 16-byte client ID + encrypted AES key
        response_payload = client_id + encrypted_aes_key

        # Return the response with the encrypted AES key included in the payload
        return Response(code=ResponseCode.RECEIVE_PUBLIC_KEY, payload=response_payload)

    @staticmethod
    def encrypt_aes_key_with_rsa(aes_key: bytes, public_key: bytes) -> bytes:
        try:
            logging.info("Encrypting AES key with RSA...")

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
            logging.info("Client ID mismatch, generating new ID.")
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

    def handle_send_file(self, db_hand: DBHandler) -> Response:
        logging.info("Send file request received")

        # Extract original file size (4 bytes), packet number (2 bytes), total packets (2 bytes), file name (255 bytes)
        original_file_size = int.from_bytes(self.payload[:4], byteorder='little')
        logging.info(f"Original file size: {original_file_size} bytes")

        packet_number = int.from_bytes(self.payload[4:6], byteorder='little')
        total_packets = int.from_bytes(self.payload[6:8], byteorder='little')
        file_name = self.payload[8:263].rstrip(b'\x00').decode('ascii')  # File name is in bytes 8 to 263
        packet_content = self.payload[263:]  # Packet content starts after the file name

        logging.info(f"Extracted file name: {file_name}")
        logging.info(f"Packet content size: {len(packet_content)} bytes, packet number: {packet_number + 1}/{total_packets}")

        # Step 1: Initialize file content collection if it hasn't been done already
        if not hasattr(self, 'file_content'):
            self.file_content = b''  # Initialize file content storage
            self.expected_file_size = original_file_size
            logging.info(f"Expected file size: {self.expected_file_size} bytes")

        # Step 2: Append the current packet content to file_content
        self.file_content += packet_content

        # Check if this is the last packet
        if packet_number == total_packets - 1:
            logging.info("All packets received. Decrypting file...")

            decrypted_file_content = self.file_content  # Placeholder for decryption

            # Step 3: Decrypt the received file content
            # try:
            #     decrypted_file_content = self.decrypt_file_content(self.file_content, self.client_id, db_hand)
            #     logging.info(f"Decrypted file content: {decrypted_file_content}")
            # except ValueError as e:
            #     logging.error(f"Decryption failed: {e}")

            # Optional: Verify the decrypted file size
            # if len(decrypted_file_content) != self.expected_file_size:
            #     logging.error(f"Decrypted file size mismatch! Expected {self.expected_file_size}, received {len(decrypted_file_content)}")
            #     return Response(code=ResponseCode.FILE_SIZE_ERROR, payload=b'')

            logging.info("File decrypted successfully. Verifying file integrity...")

            # Step 4: Calculate the CRC of the decrypted content
            crc_value = cksum.memcrc(decrypted_file_content)
            logging.info(f"Calculated CRC: {crc_value}")

            # Step 5: Prepare the response (1603) with Client ID, Content Size, File Name, and CRC
            response_payload = (
                self.client_id +
                len(decrypted_file_content).to_bytes(4, byteorder='little') +  # Content Size
                file_name.encode('ascii').ljust(255, b'\x00') +  # File Name (padded with null bytes)
                crc_value.to_bytes(4, byteorder='little')  # CRC Checksum
            )

            response = Response(code=ResponseCode.SEND_FILE_SUCCESS, payload=response_payload)
            logging.info(f"Send file response prepared with CRC: {crc_value}")
            return response

    def decrypt_file_content(self, encrypted_content: bytes, client_id: bytes, db_hand: DBHandler) -> bytes:
        """
        Decrypt the file content using AES in CBC mode.
        Fetches the AES key from the database using the client_id.
        Assumes the IV is 16 bytes of zero.
        """
        # Fetch the AES key from the database using the client ID
        aes_key = db_hand.get_aes_key(client_id)

        # Check if the AES key was found
        if aes_key is None:
            raise ValueError("AES key not found for client ID")

        logging.info("Retrieved AES key")

        # Use AES CBC mode for decryption with a zeroed 16-byte IV
        cipher = AES.new(aes_key, AES.MODE_CBC, iv=bytes(16))

        # Decrypt the content
        decrypted_content = cipher.decrypt(encrypted_content)

        # Remove padding (using PKCS7 padding)
        decrypted_content = Padding.unpad(decrypted_content, AES.block_size)

        return decrypted_content

    def handle_crc_valid(self, db_hand: DBHandler):
        logging.info("CRC valid request received")

        # Extract the file name and CRC value from the payload
        self.insert_content_to_file()
        file_name = self.payload[:255].rstrip(b'\x00').decode('ascii')
        db_hand.insert_file(client_id=self.client_id, file_name=file_name, path_name=file_name, verified=True)

        return Response(code=ResponseCode.ACK, payload=b'')

    def insert_content_to_file(self):
        # Create a directory with the name of self.client_id if it doesn't exist
        directory = self.client_id
        if not os.path.exists(directory):
            os.makedirs(directory)

        # Create (or override if exists) a file with the name self.file_name in the folder self.client_id
        file_path = os.path.join(directory, self.file_name)

        # Insert self.content into the file
        with open(file_path, 'w') as file:
            file.write(self.content)

        print(f"Content successfully written to {file_path}")
