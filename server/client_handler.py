import os
import struct
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from binascii import crc32 as memcrc
import socket
import time
from response import (
    ResponseCRCValid,
    ResponseGeneralError,
    ResponseMessageReceived,
    ResponsePublicKeyReceived,
    ResponseSignInAllowed,
    ResponseSignInRejected,
    ResponseSignUpFailed,
    ResponseSignUpSuccess,
)
from request import Request, RequestCode
from database_handler import DataBaseHandler
import utils


class ClientHandler:
    """A class to handle a client."""

    def __init__(self, client_sock: socket.socket, user_db: DataBaseHandler):
        self.sock = client_sock
        self.db = user_db
        self.last_active_time = time.time()
        self.client_id = bytes(utils.CLIENT_ID_LEN)
        self.aes_key = bytes(utils.AES_KEY_SIZE)
        self.username = ""
        self.filename = ""
        self.awaiting_file = False
        self.active = True

    def handle_message(self):
        """Handle a message from the client."""
        if not self.active:
            raise RuntimeError(f"got message on inactive client {self.client_id}")

        self.last_active_time = time.time()
        try:
            buffer = self.sock.recv(utils.MAX_REQUEST_LENGTH)
            request = Request(buffer)
            match request.code:
                case RequestCode.SIGN_UP:
                    self._sign_up(request)
                case RequestCode.SEND_PUBLIC_KEY:
                    self._send_public_key(request)
                case RequestCode.SIGN_IN:
                    self._sign_in(request)
                case RequestCode.SEND_FILE:
                    self._send_file(request)
                case RequestCode.CRC_VALID:
                    self._handle_valid_crc(request)
                case RequestCode.CRC_INVALID:
                    self._handle_invalid_crc(request)
                case RequestCode.CRC_INVALID_4TH_TIME:
                    self._handle_invalid_crc_4th_time(request)
                case _:
                    raise ValueError(f"Invalid request code {request.code}")
        except RuntimeError as e:
            print(
                f"failed to handle request with error: {str(e)}\nfrom client: {self.client_id}"
            )
            self.sock.send(ResponseGeneralError().pack())

    @staticmethod
    def _bytes_to_string(b: bytes) -> str:
        return str(b.split(bytes([ord("\0")]))[0], "utf-8")

    def _sign_up(self, request: Request):
        if self.awaiting_file:
            raise RuntimeError("got registration message in file phase")
        if request.payload_size != utils.MAX_USER_NAME_LEN:
            raise RuntimeError("wrong payload size in registration")

        username = ClientHandler._bytes_to_string(request.payload)
        if self.db.get_client_by_name(username):
            self.sock.send(ResponseSignUpFailed().pack())
            return
        self.db.create_new_client(username)
        self.client_id = self.db.get_client_by_name(username)[0]
        self.sock.send(ResponseSignUpSuccess(self.client_id).pack())

    def _send_public_key(self, request: Request):
        if self.awaiting_file:
            raise RuntimeError("got public key message in file phase")
        if request.payload_size != utils.MAX_USER_NAME_LEN + utils.PUBLIC_KEY_SIZE:
            raise RuntimeError("wrong payload size in public key")

        username = ClientHandler._bytes_to_string(request.payload[:utils.MAX_USER_NAME_LEN])
        public_key = request.payload[utils.MAX_USER_NAME_LEN:]
        if self.client_id != request.client_id or self.username != username:
            raise RuntimeError("client_id or username not matching")

        self.db.update_public_key(self.client_id, public_key)
        enc_aes_key = self._get_encrypted_aes_key(public_key)
        self.sock.send(ResponsePublicKeyReceived(self.client_id, enc_aes_key).pack())
        self.awaiting_file = True

    def _sign_in(self, request: Request):
        if self.awaiting_file:
            raise RuntimeError("got login message in file phase")
        if request.payload_size != utils.MAX_USER_NAME_LEN:
            raise RuntimeError("wrong payload size in login")
        client_row = self.db.get_client_by_id(request.client_id)
        if not client_row or not client_row[2]:
            self.sock.send(ResponseSignInRejected(request.client_id).pack())
            return
        username = ClientHandler._bytes_to_string(request.payload[:utils.MAX_USER_NAME_LEN])
        if username != client_row[1]:
            raise RuntimeError("client_id or username not matching")

        self.client_id = request.client_id
        self.username = username
        enc_aes_key = self._get_encrypted_aes_key(client_row[2])
        self.sock.send(ResponseSignInAllowed(self.client_id, enc_aes_key).pack())
        self.awaiting_file = True

    def _send_file(self, request: Request):
        if not self.awaiting_file:
            raise RuntimeError("Received file request in login phase")
        if self.client_id != request.client_id:
            raise RuntimeError("Invalid client_id")
        if request.payload_size <= 4 + utils.MAX_FILE_NAME_LEN:
            raise RuntimeError("Invalid (empty) file content")
        (content_size,) = struct.unpack("<I", request.payload[:4])
        padded_content_size = (content_size // utils.AES_KEY_SIZE) * utils.AES_KEY_SIZE
        if content_size % utils.AES_KEY_SIZE != 0:
            padded_content_size += utils.AES_KEY_SIZE
        filename = ClientHandler._bytes_to_string(
            request.payload[4: utils.MAX_FILE_NAME_LEN + 4]
        )
        encrypted_file = request.payload[
            utils.MAX_FILE_NAME_LEN + 4: utils.MAX_FILE_NAME_LEN + 4 + padded_content_size
        ]
        file_crc = self._decrypt_and_save_file(encrypted_file, content_size)
        self.sock.send(
            ResponseCRCValid(self.client_id, content_size, filename, file_crc).pack()
        )
        self.awaiting_file = False

    def _handle_valid_crc(self, request: Request):
        if self.awaiting_file:
            raise RuntimeError("Received valid crc request while waiting for file")
        if self.client_id != request.client_id:
            raise RuntimeError("Invalid client_id")
        if request.payload_size != utils.MAX_FILE_NAME_LEN:
            raise RuntimeError("Invalid payload size")
        filename = ClientHandler._bytes_to_string(request.payload)
        if filename != self.filename:
            raise RuntimeError("Invalid filename")
        self.db.set_file_to_valid(self.client_id)
        self.sock.send(ResponseMessageReceived(self.client_id).pack())

    def _handle_invalid_crc(self, request: Request):
        if self.client_id != request.client_id:
            raise RuntimeError("Invalid client_id")
        if request.payload_size != utils.MAX_FILE_NAME_LEN:
            raise RuntimeError("Invalid payload size")
        filename = ClientHandler._bytes_to_string(request.payload)
        if filename != self.filename:
            raise RuntimeError("Invalid filename")
        self.awaiting_file = True

    def _handle_invalid_crc_4th_time(self, request: Request):
        if not self.awaiting_file:
            raise RuntimeError("Received terminate request in login phase")
        if self.client_id != request.client_id:
            raise RuntimeError("Invalid client_id")
        if request.payload_size != utils.MAX_FILE_NAME_LEN:
            raise RuntimeError("Invalid payload size")
        filename = ClientHandler._bytes_to_string(request.payload)
        if filename != self.filename:
            raise RuntimeError("Invalid filename")
        self.sock.send(ResponseMessageReceived(self.client_id).pack())
        self.active = False

    def _get_encrypted_aes_key(self, public_key):
        self.aes_key = os.urandom(utils.AES_KEY_SIZE)
        self.db.update_aes_key(self.client_id, self.aes_key)

        rsa_key = RSA.import_key(public_key)
        rsa = PKCS1_OAEP.new(rsa_key)
        return rsa.encrypt(self.aes_key)

    def _decrypt_and_save_file(self, encrypted_file, content_size):
        file_content = bytes()
        for i in range(len(encrypted_file) // utils.AES_KEY_SIZE):
            aes = AES.new(self.aes_key, mode=AES.MODE_CBC, IV=bytes(utils.AES_KEY_SIZE))
            file_content += aes.decrypt(
                encrypted_file[i * utils.AES_KEY_SIZE: (i + 1) * utils.AES_KEY_SIZE]
            )
        if len(file_content) < content_size:
            raise RuntimeError("File decryption failed")
        file_content = file_content[:content_size]
        self.db.insert_unvalidated_file(self.filename, file_content, self.client_id)
        return memcrc(file_content)
