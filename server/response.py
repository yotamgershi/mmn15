from enum import Enum
from typing import Literal
import struct

VERSION = 3


def validate_response_code(code: "ResponseCode") -> None:
    """Validate that a response code is valid."""
    if code not in ResponseCode:
        raise ValueError(f"Invalid response code: {code.value}")


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
        validate_range("payload_size", self.payload_size, "uint32_t")

    def pack(self) -> bytes:
        return struct.pack(">BBI", self.version, self.code.value, self.payload_size)
