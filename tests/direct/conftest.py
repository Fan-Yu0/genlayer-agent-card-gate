import os


if os.name == "nt":
    _original_unlink = os.unlink

    def _safe_unlink(path):
        try:
            _original_unlink(path)
        except PermissionError:
            # gltest-direct replaces stdin with a temp file on Windows.
            pass

    os.unlink = _safe_unlink


def to_hex(addr_bytes):
    if hasattr(addr_bytes, "as_hex"):
        return addr_bytes.as_hex
    from genlayer.py.types import Address

    return Address(addr_bytes).as_hex
