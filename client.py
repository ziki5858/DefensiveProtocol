#!/usr/bin/env python3
import socket
import sys


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <server_ip> <port>")
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        print(f"Connected to {host}:{port}. Type 'PING' or 'exit'.")

        while True:
            line = input('> ').strip()
            if line.lower() == 'exit':
                print("Closing connection.")
                break
            if line.upper() != 'PING':
                print("Please enter exactly: PING")
                continue

            # send ping
            s.sendall((line + '\n').encode('utf-8'))

            # wait for pong
            data = s.recv(1024)
            if not data:
                print("Server closed connection.")
                break
            print(f"Received: {data.decode('utf-8').strip()}")


if __name__ == '__main__':
    main()
