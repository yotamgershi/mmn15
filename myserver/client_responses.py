
class ResponseCode:
    SIGN_UP_SUCCESS = 1600
    SIGN_UP_ERROR = 1601


class Response:
    VERSION = 3

    def __init__(self, payload: str, code: int):
        self.version = int(Response.VERSION).to_bytes(1, byteorder='little')
        self.code = int(code).to_bytes(2, byteorder='little')
        self.payload = str(payload).encode('utf-8')
        self.payload_size = len(self.payload).to_bytes(4, byteorder='little')

        self.header = (self.version, self.code, self.payload_size)

    def __str__(self):
        return f"Response(code={int.from_bytes(self.code, byteorder='little')}, payload={self.payload.decode('utf-8')})"

    def to_bytes(self) -> bytes:
        return b''.join(self.header) + self.payload
