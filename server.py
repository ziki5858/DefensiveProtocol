import socket
import threading

from protocol import Protocol
from registry import ClientRegistry
from handlers import handlers

HOST = '0.0.0.0'
PORT = 12345


def handle_client(conn, addr, registry: ClientRegistry):
    try:
        client_id, version, code, payload = Protocol.read_request(conn)
        fn = handlers.get(code)
        if fn:
            resp = fn(client_id, version, payload, registry)
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
            threading.Thread(target=handle_client, args=(conn, addr, registry), daemon=True).start()

if __name__ == '__main__':
    main()