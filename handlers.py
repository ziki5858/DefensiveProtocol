from protocol import Protocol
from registry import ClientRegistry, parse_register_payload

handlers: dict[int, callable] = {}

def register(code: int):
    def decorator(fn):
        handlers[code] = fn
        return fn
    return decorator

@register(600)
def handle_register(client_id: bytes, version: int, payload: bytes, registry: ClientRegistry) -> bytes:
    username, pubkey = parse_register_payload(payload)
    new_id = registry.register(username, pubkey)
    return Protocol.make_response(version, 2100, new_id)