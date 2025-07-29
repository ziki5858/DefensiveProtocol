import uuid
from datetime import datetime

def parse_register_payload(payload: bytes) -> tuple[str, bytes]:
    name = payload[:255].split(b'\0', 1)[0].decode('ascii')
    pubkey = payload[255:255+160]
    return name, pubkey

class ClientRegistry:
    def __init__(self):
        self._clients: dict[bytes, tuple[str, bytes, datetime]] = {}

    def register(self, username: str, public_key: bytes) -> bytes:
        new_id = uuid.uuid4().bytes
        self._clients[new_id] = (username, public_key, datetime.utcnow())
        return new_id

    def get_all(self) -> dict[bytes, tuple[str, bytes, datetime]]:
        return dict(self._clients)