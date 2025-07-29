# server.py

import socket
import threading

from protocol import Protocol
from registry import ClientRegistry
from handlers import HANDLERS, HandlerContext

HOST = '0.0.0.0'
PORT = 12345

def handle_client(conn, addr, registry: ClientRegistry):
    """
    Read a request, dispatch to the appropriate handler, and send response.
    """
    try:
        client_id, version, code, payload = Protocol.read_request(conn)
        # bundle all into context
        ctx = HandlerContext(client_id, version, payload, registry)

        # look up handler by code
        fn = HANDLERS.get(code)
        if fn:
            resp = fn(ctx)
        else:
            resp = Protocol.make_response(version, 9000)

        conn.sendall(resp)
    finally:
        conn.close()

def main():
    registry = ClientRegistry()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(
                target=handle_client,
                args=(conn, addr, registry),
                daemon=True
            ).start()

if __name__ == '__main__':
    main()

