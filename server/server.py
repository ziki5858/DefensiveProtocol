#!/usr/bin/env python3
import socket
import threading
import os
import logging

from protocol import Protocol
from registry import ClientRegistry
from handlers import HANDLERS, HandlerContext

logging.basicConfig(level=logging.INFO)

SERVER_VERSION = 1
HOST = '0.0.0.0'
DEFAULT_PORT = 1357
CONFIG_FILE = 'myport.info'

# Dynamically read the port from the configuration file
PORT = DEFAULT_PORT
if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            PORT = int(f.read().strip())
    except ValueError:
        logging.warning(f"Invalid port value in {CONFIG_FILE}, using default {DEFAULT_PORT}")
else:
    logging.warning(f"{CONFIG_FILE} not found, using default port {DEFAULT_PORT}")


def handle_client(conn, addr, registry: ClientRegistry):
    logging.info(f"Connection from {addr}")
    try:
        while True:
            try:
                client_id, version, code, payload = Protocol.read_request(conn)
                ctx = HandlerContext(client_id, version, payload, registry)
                handler = HANDLERS.get(code)

                if handler:
                    logging.info(f"Handling request code {code}")
                    response = handler(ctx)
                    if code != 600:
                        registry.update_last_seen(client_id)
                else:
                    logging.warning(f"Unknown request code {code}, sending error 9000")
                    response = Protocol.make_response(SERVER_VERSION, 9000)

            except Exception as e:
                logging.error(f"Failed to process request from {addr}: {e}")
                response = Protocol.make_response(SERVER_VERSION, 9000)

            try:
                conn.sendall(response)
            except Exception as e:
                logging.error(f"Failed to send response to {addr}: {e}")
                break

    except Exception as e:
        logging.error(f"Outer exception: {e}")
    finally:
        logging.info(f"Connection closed from {addr}")
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
