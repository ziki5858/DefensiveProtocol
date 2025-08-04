#!/usr/bin/env python3
import socket
import threading
import os
import logging
import struct

from protocol import Protocol
from registry import ClientRegistry
from handlers import HANDLERS, HandlerContext

logging.basicConfig(level=logging.INFO)

HOST = '0.0.0.0'
DEFAULT_PORT = 1357
CONFIG_FILE = 'myport.info'

# Dynamically read the port from the configuration file
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            PORT = int(f.read().strip())
    except ValueError:
        logging.warning(f"Invalid port value in {CONFIG_FILE}, using default {DEFAULT_PORT}")
        PORT = DEFAULT_PORT
else:
    logging.warning(f"{CONFIG_FILE} not found, using default port {DEFAULT_PORT}")
    PORT = DEFAULT_PORT


def handle_client(conn, addr, registry: ClientRegistry):
    print(f"[INFO] Connection from {addr}")
    try:
        while True:
            try:
                client_id, version, code, payload = Protocol.read_request(conn)
                print(f"[DEBUG] Received request from {addr}")
                print(f"[DEBUG] Code: {code}")
                print(f"[DEBUG] Client ID: {client_id.hex()}")
                print(f"[DEBUG] Payload size: {len(payload)} bytes")
            except Exception as e:
                print(f"[ERROR] Failed to read request: {e}")
                break

            ctx = HandlerContext(client_id, version, payload, registry)
            handler = HANDLERS.get(code)

            if handler:
                print(f"[INFO] Handling request code {code}")
                response = handler(ctx)
            else:
                print(f"[WARN] Unknown request code {code}, sending error 9000")
                response = Protocol.make_response(version, 9000)

            conn.sendall(response)

    except Exception as e:
        print(f"[ERROR] Outer exception: {e}")
    finally:
        print(f"[INFO] Connection closed from {addr}")
        conn.close()


def main():
    # Initialize the client registry
    registry = ClientRegistry()

    # Create and bind the listening socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen()
        logging.info(f"Server listening on {HOST}:{PORT}")

        while True:
            # Accept a new client connection
            conn, addr = server_socket.accept()
            # Spawn a new thread to handle client requests
            threading.Thread(
                target=handle_client,
                args=(conn, addr, registry),
                daemon=True
            ).start()


if __name__ == '__main__':
    main()
