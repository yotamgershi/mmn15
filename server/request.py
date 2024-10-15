import struct
from typing import Literal
from enum import Enum


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


def validate_range(
    var_name: str,
    number: int,
    uint_type: Literal["uint8_t", "uint16_t", "uint32_t", "uint64_t"],
) -> None:
    """Validate that a number is within the range of a given unsigned integer type."""
    ranges = {
        "uint8_t": (0, 0xFF),
        "uint16_t": (0, 0xFFFF),
        "uint32_t": (0, 0xFFFFFFFF),
        "uint64_t": (0, 0xFFFFFFFFFFFFFFFF),
    }
    min_val, max_val = ranges[uint_type]
    if not min_val <= number <= max_val:
        raise ValueError(f"{var_name} {number} is out of range for {uint_type}.")


class RequestCode(Enum):
    """Request codes for the client to send to the server."""

    SIGN_UP = 825
    SEND_PUBLIC_KEY = 826
    SIGN_IN = 827
    SEND_FILE = 828
    CRC_VALID = 900
    CRC_INVALID = 901
    CRC_INVALID_4TH_TIME = 902


class Request:

    def __init__(self, buffer: bytes):
        if len(buffer) < REQUEST_MIN_LEN:
            raise ValueError(f"Request too short - {len(buffer)} bytes, expected at least {REQUEST_MIN_LEN}")

        # Extract client ID (16 bytes)
        self.client_id = buffer[:CLIENT_ID_LEN]
        buffer = buffer[CLIENT_ID_LEN:]

        # Ensure buffer has enough data for header (6 bytes: version, code, and payload_size)
        if len(buffer) < 6:
            raise ValueError("Header too short, cannot unpack version, code, and payload size.")

        # Unpack header: version (1 byte), code (1 byte), payload_size (4 bytes)
        self.version, self.code, self.payload_size = struct.unpack(">BBI", buffer[:6])
        self.code = RequestCode(self.code)

        # Validate extracted fields
        validate_request_code(self.code)
        validate_range("payload_size", self.payload_size, "uint32_t")
        validate_range("version", self.version, "uint8_t")

        buffer = buffer[6:]  # Remaining buffer is the payload

        # Validate that the payload size matches the remaining buffer length
        if len(buffer) != self.payload_size:
            raise ValueError(f"Payload size mismatch: expected {self.payload_size}, got {len(buffer)}")

        # Store the payload
        self.payload = buffer
