
class ResponseCode:
    SIGN_UP_SUCCESS = 1600
    SIGN_UP_ERROR = 1601
    RECEIVE_PUBLIC_KEY = 1602


class Response:
    VERSION = 3

    def __init__(self, code: int, payload: bytes | str):
        self.version = int(Response.VERSION).to_bytes(1, byteorder='little')
        self.code = int(code).to_bytes(2, byteorder='little')

        # If the payload is a string, encode it to bytes; otherwise, treat it as bytes
        if isinstance(payload, str):
            self.payload = payload.encode('utf-8')  # Text data, encode to bytes
        elif isinstance(payload, bytes):
            self.payload = payload  # Binary data, use it as-is
        else:
            raise TypeError("Payload must be either a string or bytes.")

        self.payload_size = len(self.payload).to_bytes(4, byteorder='little')
        self.header = (self.version, self.code, self.payload_size)

    def __str__(self):
        try:
            # Attempt to decode payload as UTF-8, fallback to display as hex for binary data
            clean_payload = self.payload.decode('utf-8')
        except UnicodeDecodeError:
            clean_payload = self.payload.hex()  # Display binary data as hexadecimal

        return f"Response(code={int.from_bytes(self.code, byteorder='little')}, payload={clean_payload})"

    def to_bytes(self) -> bytes:
        # Return the full response as bytes: header + payload
        return b''.join(self.header) + self.payload
