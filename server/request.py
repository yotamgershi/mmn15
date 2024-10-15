import struct
from enum import Enum
import utils


def validate_request_code(code: "RequestCode") -> None:
    """Validate that a request code is valid."""
    if code not in RequestCode:
        raise ValueError(f"Invalid reqeust code: {code.value}")


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
        if len(buffer) < utils.REQUEST_MIN_LEN:
            raise ValueError(f"Request too short - {len(buffer)} bytes, expected at least {utils.REQUEST_MIN_LEN}")

        # Extract client ID (16 bytes)
        self.client_id = buffer[:utils.CLIENT_ID_LEN]
        buffer = buffer[utils.CLIENT_ID_LEN:]

        # Ensure buffer has enough data for header (6 bytes: version, code, and payload_size)
        if len(buffer) < 6:
            raise ValueError("Header too short, cannot unpack version, code, and payload size.")

        # Unpack header: version (1 byte), code (1 byte), payload_size (4 bytes)
        self.version, self.code, self.payload_size = struct.unpack(">BBI", buffer[:6])
        self.code = RequestCode(self.code)

        # Validate extracted fields
        validate_request_code(self.code)
        utils.validate_range("payload_size", self.payload_size, "uint32_t")
        utils.validate_range("version", self.version, "uint8_t")

        buffer = buffer[6:]  # Remaining buffer is the payload

        # Validate that the payload size matches the remaining buffer length
        if len(buffer) != self.payload_size:
            raise ValueError(f"Payload size mismatch: expected {self.payload_size}, got {len(buffer)}")

        # Store the payload
        self.payload = buffer
