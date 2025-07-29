import struct


class Protocol:
    HEADER_FMT = '<16s B H I'  # little-endian: 16s=client_id, B=version, H=code, I=payload_size
    HEADER_SIZE = struct.calcsize(HEADER_FMT)

    @staticmethod
    def recv_exact(conn, n: int) -> bytes:
        buf = b''
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Connection closed")
            buf += chunk
        return buf

    @classmethod
    def read_request(cls, conn) -> tuple[bytes, int, int, bytes]:
        header = cls.recv_exact(conn, cls.HEADER_SIZE)
        client_id, version, code, size = struct.unpack(cls.HEADER_FMT, header)
        payload = cls.recv_exact(conn, size) if size else b''
        return client_id, version, code, payload

    @classmethod
    def make_response(cls, version: int, code: int, payload: bytes = b'') -> bytes:
        header = struct.pack(cls.HEADER_FMT, b'\0' * 16, version, code, len(payload))
        return header + payload
