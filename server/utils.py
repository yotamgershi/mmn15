from typing import Literal

VERSION = 3

CLIENT_ID_LEN = 16
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 16
ENCRYPTED_AES_KEY_SIZE = 128
MAX_USER_NAME_LEN = 255
MAX_FILE_NAME_LEN = 255

REQUEST_MIN_LEN = 23
MAX_FILE_CONTENT_LENGTH = 0xFFFFFFFF
MAX_REQUEST_LENGTH = REQUEST_MIN_LEN + MAX_FILE_NAME_LEN + 4 + MAX_FILE_CONTENT_LENGTH

DEFAULT_PORT = 1256


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
