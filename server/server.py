import socket
import selectors
from enum import Enum

VERSION = 3
DEFAULT_PORT = 1256
PORT_FILE = "port.info"

CLIENT_ID_LEN = 16
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 16
ENCRYPTED_AES_KEY_SIZE = 128
MAX_USER_NAME_LEN = 255
MAX_FILE_NAME_LEN = 255

REQUEST_MIN_LEN = 23
MAX_FILE_CONTENT_LENGTH = 0xFFFFFFFF
MAX_REQUEST_LENGTH = REQUEST_MIN_LEN + MAX_FILE_NAME_LEN + 4 + MAX_FILE_CONTENT_LENGTH


def validate_request_code(code: "RequestCode") -> None:
    """Validate that a request code is valid."""
    if code not in RequestCode:
        raise ValueError(f"Invalid reqeust code: {code.value}")


def validate_response_code(code: "ResponseCode") -> None:
    """Validate that a response code is valid."""
    if code not in ResponseCode:
        raise ValueError(f"Invalid response code: {code.value}")


class RequestCode(Enum):
    """Request codes for the client to send to the server."""

    SIGN_UP = 825
    SEND_PUBLIC_KEY = 826
    SIGN_IN = 827
    SEND_FILE = 828
    CRC_VALID = 900
    CRC_INVALID = 901
    CRC_INVALID_4TH_TIME = 902


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


class Request:

    def __init__(self, buffer: bytes):
        if len(buffer) < REQUEST_MIN_LEN:
            raise ValueError("Request too short - %d bytes" % len(buffer))
        self.client_id = buffer[:CLIENT_ID_LEN]
        buffer = buffer[CLIENT_ID_LEN:]

