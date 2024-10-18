from uuid import uuid4

request_codes = {
    "SIGN_UP": 825,
}


class Request:
    CLIENT_ID_SIZE = 16
    VERSION_SIZE = 1
    CODE_SIZE = 2
    PAYLOAD_SIZE_SIZE = 4

    def __init__(self, client_id: bytes, version: bytes, code: bytes, payload_size: bytes):
        self.client_id = client_id
        self.version = version
        self.code = code
        self.payload_size = payload_size
        self.validate()

    def validate(self):
        if not (0 <= len(self.client_id) <= 16):
            raise ValueError(f"Client ID must be between 0 and 16 (16 bytes), got {self.client_id}.")
        if not (0 <= self.version <= 2**8 - 1):
            raise ValueError(f"Version must be between 0 and 255 (1 byte), got {self.version}.")
        if not (0 <= self.code <= 2**16 - 1):
            raise ValueError(f"Code must be between 0 and 65535 (2 bytes), got {self.code}.")
        if not (0 <= self.payload_size <= 2**32 - 1):
            raise ValueError(f"Payload size must be between 0 and 4294967295 (4 bytes), got {self.payload_size}.")

    def build_header(self):
        header = (self.client_id, self.version, self.code, self.payload_size)
        return header

    def build_request(self):
        return NotImplementedError("Subclasses must implement this method.")


class SignUpRequest(Request):
    MAX_PAYLOAD_SIZE = 255

    def __init__(self, client_id: bytes, version: bytes, code: bytes, payload_size: bytes, payload: bytes):
        client_id = SignUpRequest.generate_client_id()

        super().__init__(client_id, version, code, payload_size)
        if payload[-1:] != b'\0':
            payload += b'\0'
        if len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload must be at most 255 bytes, got {len(payload)} bytes.")

        # self.client_id = SignUpRequest.generate_client_id()
        self.payload = payload.ljust(self.MAX_PAYLOAD_SIZE, b'\0')
        print(f"Sign-up request created: client_id={client_id}, version={version}, code={code}, payload_size={payload_size}, payload={payload}")

    @staticmethod
    def generate_client_id():
        return uuid4().bytes

    def build_request(self):
        header = self.build_header()
        request = self.payload
        print(f"Sending sign-up request: {header + request}")
        return header + request
