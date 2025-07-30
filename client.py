#!/usr/bin/env python3
import socket
import struct
import sys


def main():

    host = '127.0.0.1'
    port = 12345

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Connected to {host}:{port}. Type 'PING' or 'exit'.")

        while True:
            line = input('> ').strip()
            if line.lower() == 'exit':
                print("Closing connection.")
                break
            if line.upper() == 'REGISTER':
                client_id = b"0" * 16
                version = 1
                code = 600
                payload_size = 415
                header = struct.pack('<16s B H I', client_id, version, code, payload_size)

                name = "Ishay"
                pubkey = b'\0' * 160
                payload = name.encode('ascii').ljust(255, b'\0') + pubkey
                packet = header + payload

            # send ping
            s.sendall(packet)

            # wait for pong
            data = s.recv(1024)
            if not data:
                print("Server closed connection.")
                break
            print(f"Received: {data.hex()}")


if __name__ == '__main__':
    main()
