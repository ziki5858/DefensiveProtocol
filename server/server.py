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
    """
    Handle multiple requests over the same connection:
    Keep reading until the client closes the socket.
    """
    try:
        while True:
            # Read request from client
            client_id, version, code, payload = Protocol.read_request(conn)
            ctx = HandlerContext(client_id, version, payload, registry)

            # Find the appropriate handler and generate response
            handler = HANDLERS.get(code)
            response = handler(ctx) if handler else Protocol.make_response(version, 9000)

            # Send response back to client
            conn.sendall(response)
    except (ConnectionError, struct.error):
        # Client disconnected or parsing error occurred
        pass
    finally:
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
