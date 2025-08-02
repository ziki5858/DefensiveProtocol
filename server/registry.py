# registry.py

import uuid
from datetime import datetime
from typing import Dict, Tuple, List, Optional

def parse_register_payload(payload: bytes) -> Tuple[str, bytes]:
    name = payload[:255].split(b'\0', 1)[0].decode('ascii')
    pubkey = payload[255:255+160]
    return name, pubkey

class ClientRegistry:
    def __init__(self):
        # client_id → (username, public_key, timestamp)
        self._clients: Dict[bytes, Tuple[str, bytes, datetime]] = {}
        # message storage: (msg_id, to_client, from_client, msg_type, content)
        self._messages: List[Tuple[int, bytes, bytes, int, bytes]] = []
        self._next_msg_id: int = 1

    def register(self, username: str, public_key: bytes) -> bytes:
        new_id = uuid.uuid4().bytes
        self._clients[new_id] = (username, public_key, datetime.utcnow())
        return new_id

    def get_all(self) -> Dict[bytes, Tuple[str, bytes, datetime]]:
        return dict(self._clients)

    def get_public_key(self, client_id: bytes) -> Optional[bytes]:
        rec = self._clients.get(client_id)
        return rec[1] if rec else None

    def store_message(self,
                      from_client: bytes,
                      to_client: bytes,
                      msg_type: int,
                      content: bytes) -> int:
        msg_id = self._next_msg_id
        self._next_msg_id += 1
        self._messages.append((msg_id, to_client, from_client, msg_type, content))
        return msg_id

    def fetch_messages(self, to_client: bytes) -> List[Tuple[int, bytes, bytes, int, bytes]]:
        """
        Remove and return all pending messages for 'to_client'.
        Each tuple is (msg_id, to_client, from_client, msg_type, content).
        """
        pending = [m for m in self._messages if m[1] == to_client]
        self._messages = [m for m in self._messages if m[1] != to_client]
        return pending
