# handlers.py

import struct
from typing import Callable, Dict, Tuple

from protocol import Protocol
from registry import ClientRegistry, parse_register_payload


class HandlerContext:
    def __init__(self, client_id: bytes, version: int, payload: bytes, registry: ClientRegistry):
        self.client_id = client_id
        self.version = version
        self.payload = payload
        self.registry = registry

    def parse_register(self) -> Tuple[str, bytes]:
        # parse username and public key from registration payload
        return parse_register_payload(self.payload)

def handle_register(ctx: HandlerContext) -> bytes:
    """
    Handle registration requests (code 600).
    Return response code 2100 with new client_id.
    """
    username, pubkey = ctx.parse_register()
    new_id = ctx.registry.register(username, pubkey)
    print(f"[DEBUG] Sending response: code=2100, payload={new_id.hex()} length={len(new_id)}")
    return Protocol.make_response(ctx.version, 2100, new_id)



def handle_users_list(ctx: HandlerContext) -> bytes:
    """
    Handle clients list requests (code 601).
    Return response code 2101 with binary list of other clients.
    """
    entries = []
    for uid, (name, _, _) in ctx.registry.get_all().items():
        if uid == ctx.client_id:
            continue
        entry = uid
        name_bytes = name.encode('ascii') + b'\0'
        entry += name_bytes.ljust(255, b'\0')
        entries.append(entry)
    body = b''.join(entries)
    return Protocol.make_response(ctx.version, 2101, body)


def handle_get_public_key(ctx: HandlerContext) -> bytes:
    """
    Handle public key requests (code 602).
    Return response code 2102 with target client_id + public_key.
    """
    target_id = ctx.payload
    public_key = ctx.registry.get_public_key(target_id)
    if public_key is None:
        return Protocol.make_response(ctx.version, 9000)
    return Protocol.make_response(ctx.version, 2102, target_id + public_key)


def handle_send_message(ctx: HandlerContext) -> bytes:
    """
    Handle message sending requests (code 603):
      • parse: [16s to_client][1B msg_type][4B content_size][content…]
      • dispatch by msg_type
      • store message and return response 2103: [16s to_client][4B message_id]
    """
    data = ctx.payload
    to_id = data[:16]
    msg_type = data[16]
    content_sz = struct.unpack('<I', data[17:21])[0]
    content = data[21:21 + content_sz]

    if msg_type == 1:
        processed = handle_key_request(ctx, to_id, content)
    elif msg_type == 2:
        processed = handle_symkey_transfer(ctx, to_id, content)
    elif msg_type == 3:
        processed = handle_text_message(ctx, to_id, content)
    elif msg_type == 4:
        processed = handle_file_transfer(ctx, to_id, content)
    else:
        return Protocol.make_response(ctx.version, 9000)

    msg_id = ctx.registry.store_message(
        from_client=ctx.client_id,
        to_client=to_id,
        msg_type=msg_type,
        content=processed
    )
    resp_body = to_id + struct.pack('<I', msg_id)
    return Protocol.make_response(ctx.version, 2103, resp_body)


def handle_fetch_messages(ctx: HandlerContext) -> bytes:
    """
    Handle message fetch requests (code 604).
    Response code 2104 with entries:
      [16s from_client][4B msg_id][1B msg_type][4B size][content…]
    """
    parts = []
    for msg_id, to_client, from_client, msg_type, content in ctx.registry.fetch_messages(ctx.client_id):
        entry = from_client
        entry += struct.pack('<I B I', msg_id, msg_type, len(content))
        entry += content
        parts.append(entry)
    return Protocol.make_response(ctx.version, 2104, b''.join(parts))


def handle_key_request(ctx: HandlerContext, to_id: bytes, content: bytes) -> bytes:
    """
    Handle message type 1 (key request):
      • look up the target client’s public key in the registry
      • return the 160-byte public key as the message content
    """
    # retrieve public key for the requested client
    public_key = ctx.registry.get_public_key(to_id)
    # if not found, return empty bytes (client will see no key)
    return public_key or b''


def handle_symkey_transfer(ctx: HandlerContext, to_id: bytes, content: bytes) -> bytes:
    """
    Handle message type 2 (symmetric key transfer):
      • verify the recipient exists
      • store the encrypted symmetric key blob as-is
      • return the original blob so it will be delivered to the recipient
    """
    # ensure the recipient is registered
    if ctx.registry.get_public_key(to_id) is None:
        # unknown recipient → nothing to store
        return b''
    # the content is already encrypted by the sender with the recipient's public key
    return content


def handle_text_message(ctx: HandlerContext, to_id: bytes, content: bytes) -> bytes:
    """
    Handle message type 3 (text message):
      • verify the recipient exists
      • (optional) filter or process the text
      • return the text content to be stored and later delivered
    """
    # ensure the recipient is registered
    if ctx.registry.get_public_key(to_id) is None:
        return b''
    # here you could sanitize or moderate the text before forwarding
    return content


def handle_file_transfer(ctx: HandlerContext, to_id: bytes, content: bytes) -> bytes:
    """
    Handle message type 4 (file transfer):
      • verify the recipient exists
      • save the raw file bytes (if desired) or forward as-is
      • return the file content to be stored and later delivered
    """
    # ensure the recipient is registered
    if ctx.registry.get_public_key(to_id) is None:
        return b''
    # optionally, save content to disk:
    # filename = f"uploads/{uuid.uuid4().hex}"
    # with open(filename, "wb") as f:
    #     f.write(content)
    return content


# map request codes to handler functions
HANDLERS: Dict[int, Callable[[HandlerContext], bytes]] = {
    600: handle_register,
    601: handle_users_list,
    602: handle_get_public_key,
    603: handle_send_message,
    604: handle_fetch_messages,
}
