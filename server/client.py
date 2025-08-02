#!/usr/bin/env python3
import socket
import struct
import os
import logging

# ---------------------------------------------
#  Dynamic settings: read the port like the server does
# ---------------------------------------------
DEFAULT_PORT = 1357
CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    'myport.info'
)

if os.path.exists(CONFIG_FILE):
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            PORT = int(f.read().strip())
    except ValueError:
        logging.warning(
            f"Invalid port in {CONFIG_FILE}, using default {DEFAULT_PORT}"
        )
        PORT = DEFAULT_PORT
else:
    logging.warning(
        f"{CONFIG_FILE} not found, using default port {DEFAULT_PORT}"
    )
    PORT = DEFAULT_PORT

HOST = '127.0.0.1'
VERSION = 1

# ---------------------------------------------
#  Helper function to show available commands
# ---------------------------------------------

def print_help():
    print("""
Available commands:
  REGISTER
  USERS
  GETPK <client_id_hex>
  KEYREQ <client_id_hex>
  SYMKEY <client_id_hex> <hex_blob>
  SENDTEXT <client_id_hex> <message>
  SENDFILE <client_id_hex> <file_path>
  EXIT
""")

# ---------------------------------------------
#  Build a packet according to the protocol
# ---------------------------------------------

def make_packet(client_id: bytes, code: int, payload: bytes) -> bytes:
    header = struct.pack('<16s B H I', client_id, VERSION, code, len(payload))
    return header + payload

# Local client ID will be assigned by the server after REGISTER (response 2100)
my_client_id = b'\0' * 16

# ---------------------------------------------
#  Validate server responses according to spec
# ---------------------------------------------

def validate_response(ver: int, code: int, size: int, body: bytes):
    assert ver == VERSION, f"Unexpected version: got {ver}, want {VERSION}"
    if code == 2100:
        assert size == 16, f"2100 payload size should be 16, got {size}"
    elif code == 2101:
        entry = 16 + 255
        assert size % entry == 0, f"2101 payload must be multiple of {entry}, got {size}"
    elif code == 2102:
        assert size == 16 + 160, f"2102 payload size should be 176, got {size}"
    elif code == 2103:
        assert size == 20, f"2103 payload size should be 20, got {size}"
    elif code == 2104:
        assert size == len(body), "2104 size header mismatch"
        assert size >= (16 + 4 + 1 + 4) or size == 0, "2104 too small for any record"
    else:
        raise AssertionError(f"Unexpected response code: {code}")

# ---------------------------------------------
#  Start client
# ---------------------------------------------

def main():
    global my_client_id
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}.")
        print_help()

        while True:
            line = input('> ').strip()
            if not line:
                continue
            parts = line.split(' ', 2)
            cmd = parts[0].upper()

            if cmd == 'REGISTER':
                name = input("Username: ").strip()
                public_key = b'\0' * 160
                payload = name.encode('ascii').ljust(255, b'\0') + public_key
                packet = make_packet(my_client_id, 600, payload)

            elif cmd == 'USERS':
                packet = make_packet(my_client_id, 601, b'')

            elif cmd == 'GETPK' and len(parts) >= 2:
                try:
                    target_id = bytes.fromhex(parts[1])
                    packet = make_packet(my_client_id, 602, target_id)
                except ValueError:
                    print("Invalid client_id hex.")
                    continue

            # Key request (msg_type=1)
            elif cmd == 'KEYREQ' and len(parts) >= 2:
                try:
                    to_id = bytes.fromhex(parts[1])
                except ValueError:
                    print("Invalid client_id hex.")
                    continue
                header = to_id + bytes([1]) + struct.pack('<I', 0)
                packet = make_packet(my_client_id, 603, header)

            # Symmetric-key transfer (msg_type=2)
            elif cmd == 'SYMKEY' and len(parts) == 3:
                try:
                    to_id = bytes.fromhex(parts[1])
                    sym_blob = bytes.fromhex(parts[2])
                except ValueError:
                    print("Invalid hex data.")
                    continue
                header = to_id + bytes([2]) + struct.pack('<I', len(sym_blob))
                packet = make_packet(my_client_id, 603, header + sym_blob)

            elif cmd == 'SENDTEXT' and len(parts) == 3:
                try:
                    to_id = bytes.fromhex(parts[1])
                except ValueError:
                    print("Invalid client_id hex.")
                    continue
                text_bytes = parts[2].encode('utf-8')
                header = to_id + bytes([3]) + struct.pack('<I', len(text_bytes))
                packet = make_packet(my_client_id, 603, header + text_bytes)

            elif cmd == 'SENDFILE' and len(parts) == 3:
                try:
                    to_id = bytes.fromhex(parts[1])
                except ValueError:
                    print("Invalid client_id hex.")
                    continue
                file_path = parts[2].strip('"')
                if not os.path.isfile(file_path):
                    print("File not found.")
                    continue
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                header = to_id + bytes([4]) + struct.pack('<I', len(file_data))
                packet = make_packet(my_client_id, 603, header + file_data)

            elif cmd == 'EXIT':
                print("Exiting.")
                break

            else:
                print("Unknown command or wrong arguments.")
                print_help()
                continue

            # Send packet and receive response
            s.sendall(packet)
            resp = s.recv(4096)
            if not resp:
                print("Server closed connection.")
                break

            # Parse and validate response
            ver, code, size = struct.unpack('<B H I', resp[:7])
            body = resp[7:]
            print(f"Response: version={ver}, code={code}, size={size}")
            validate_response(ver, code, size, body)

            # Display response details
            if code == 2100:
                my_client_id = body
                print(f"REGISTERED: client_id = {my_client_id.hex()}")

            elif code == 2101:
                entry_size = 16 + 255
                count = size // entry_size
                print(f"USERS LIST: {count} user(s)")
                for i in range(count):
                    chunk = body[i*entry_size:(i+1)*entry_size]
                    uid = chunk[:16].hex()
                    name = chunk[16:].split(b'\0', 1)[0].decode('ascii')
                    print(f"  - ID: {uid} | Name: {name}")

            elif code == 2102:
                uid = body[:16].hex()
                pubkey = body[16:]
                print(f"GETPK RESPONSE for ID: {uid}")
                print(f" Public Key ({len(pubkey)} bytes): {pubkey.hex()}")

            elif code == 2103:
                to_id = body[:16].hex()
                msg_id, = struct.unpack('<I', body[16:20])
                print(f"SEND RESPONSE → To ID: {to_id} | Message ID: {msg_id}")

            elif code == 2104:
                offset = 0
                print(f"FETCH RESPONSE: payload {size} bytes")
                while offset < size:
                    from_id = body[offset:offset+16].hex(); offset += 16
                    msg_id, = struct.unpack('<I', body[offset:offset+4]); offset += 4
                    msg_type = body[offset]; offset += 1
                    content_size, = struct.unpack('<I', body[offset:offset+4]); offset += 4
                    content = body[offset:offset+content_size]; offset += content_size
                    if msg_type == 3:
                        text = content.decode('utf-8', errors='replace')
                        print(f"  • From {from_id} | MsgID={msg_id} | Text: '{text}'")
                    elif msg_type == 4:
                        print(f"  • From {from_id} | MsgID={msg_id} | File transfer ({content_size} bytes)")
                    else:
                        print(f"  • From {from_id} | MsgID={msg_id} | Type={msg_type} | {content_size} bytes")

            else:
                print("Unrecognized or error response.")

if __name__ == '__main__':
    main()
