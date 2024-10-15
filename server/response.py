from enum import Enum
import struct
import utils

VERSION = 3


def validate_response_code(code: "ResponseCode") -> None:
    """Validate that a response code is valid."""
    if code not in ResponseCode:
        raise ValueError(f"Invalid response code: {code.value}")


class ResponseCode(Enum):
    """Response codes for the server to send to the client."""

    SIGN_UP_SUCCEEDED = 1600
    SIGN_UP_FAILED = 1601
    PUBLIC_KEY_RECEIVED = 1602
    CRC_VALID = 1603
    MESSAGE_RECEIVED = 1604
    SIGN_IN_ALLOWED = 1605
    SIGN_IN_REJECTED = 1606
    GENERAL_ERROR = 1607


class Response:
    def __init__(self, code: ResponseCode, payload_size: int):
        self.version = VERSION
        self.code = code
        self.payload_size = payload_size
        validate_response_code(self.code)
        utils.validate_range("payload_size", self.payload_size, "uint32_t")

    def pack(self) -> bytes:
        return struct.pack(">BBI", self.version, self.code.value, self.payload_size)


class ResponseSignUpSuccess(Response):
    def __init__(self, client_id: bytes):
        super().__init__(ResponseCode.SIGN_UP_SUCCEEDED, utils.CLIENT_ID_LEN)
        if len(client_id) != utils.CLIENT_ID_LEN:
            raise ValueError(f"Client ID must be {utils.CLIENT_ID_LEN} bytes long.")
        self.client_id = client_id

    def pack(self) -> bytes:
        return super().pack() + self.client_id


class ResponseSignUpFailed(Response):
    def __init__(self, error_message: str):
        super().__init__(ResponseCode.SIGN_UP_FAILED, len(error_message))


class ResponsePublicKeyReceived(Response):
    def __init__(self, client_id: bytes, encrypted_aes_key: bytes):
        super().__init__(ResponseCode.PUBLIC_KEY_RECEIVED, utils.CLIENT_ID_LEN + utils.ENCRYPTED_AES_KEY_SIZE)
        if len(client_id) != utils.CLIENT_ID_LEN:
            raise ValueError(f"Client ID must be {utils.CLIENT_ID_LEN} bytes long.")
        if len(encrypted_aes_key) != utils.ENCRYPTED_AES_KEY_SIZE:
            raise ValueError(f"Encrypted AES key must be {utils.ENCRYPTED_AES_KEY_SIZE} bytes long.")
        self.client_id = client_id
        self.encrypted_aes_key = encrypted_aes_key

    def pack(self) -> bytes:
        return super().pack() + self.client_id + self.encrypted_aes_key


class ResponseCRCValid(Response):
    def __init__(self, client_id: bytes, content_size: int, file_name: str, crc: int):
        super().__init__(ResponseCode.CRC_VALID, utils.CLIENT_ID_LEN + 4 + utils.MAX_FILE_NAME_LEN + 4)
        if len(client_id) != utils.CLIENT_ID_LEN:
            raise ValueError(f"Client ID must be {utils.CLIENT_ID_LEN} bytes long.")
        if len(file_name) > utils.MAX_FILE_NAME_LEN:
            raise ValueError(f"File name must be at most {utils.MAX_FILE_NAME_LEN} characters long.")
        self.client_id = client_id
        self.content_size = content_size
        self.file_name = bytes(file_name, "utf-8")
        self.crc = crc

    def pack(self) -> bytes:
        return (super().pack() + self.client_id + struct.pack("<I", self.content_size) + self.file_name
                + b"\0" * (utils.MAX_FILE_NAME_LEN - len(self.file_name)) * struct.pack("<I", self.crc))


class ResponseMessageReceived(Response):
    def __init__(self, client_id: bytes):
        super().__init__(ResponseCode.MESSAGE_RECEIVED, utils.CLIENT_ID_LEN)
        if len(client_id) != utils.CLIENT_ID_LEN:
            raise ValueError(f"Client ID must be {utils.CLIENT_ID_LEN} bytes long.")
        self.client_id = client_id

    def pack(self) -> bytes:
        return super().pack() + self.client_id


class ResponseSignInAllowed(Response):
    def __init__(self, client_id: bytes, encrypted_aes_key: bytes):
        super().__init__(ResponseCode.SIGN_IN_ALLOWED, utils.CLIENT_ID_LEN + utils.ENCRYPTED_AES_KEY_SIZE)
        if len(client_id) != utils.CLIENT_ID_LEN:
            raise ValueError(f"Client ID must be {utils.CLIENT_ID_LEN} bytes long.")
        if len(encrypted_aes_key) != utils.ENCRYPTED_AES_KEY_SIZE:
            raise ValueError(f"Encrypted AES key must be {utils.ENCRYPTED_AES_KEY_SIZE} bytes long.")
        self.client_id = client_id
        self.encrypted_aes_key = encrypted_aes_key

    def pack(self):
        return super().pack() + self.client_id + self.encrypted_aes_key


class ResponseSignInRejected(Response):
    def __init__(self, client_id: bytes):
        super().__init__(ResponseCode.SIGN_IN_REJECTED, utils.CLIENT_ID_LEN)
        if len(client_id) != utils.CLIENT_ID_LEN:
            raise ValueError(f"Client ID must be {utils.CLIENT_ID_LEN} bytes long.")
        self.client_id = client_id

    def pack(self):
        return super().pack() + self.client_id


class ResponseGeneralError(Response):
    def __init__(self, error_message: str):
        super().__init__(ResponseCode.GENERAL_ERROR, 0)
