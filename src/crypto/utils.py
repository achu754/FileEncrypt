import os
import secrets


def generate_salt(length: int = 32) -> bytes:
    """Generate cryptographically secure random salt."""
    return secrets.token_bytes(length)


def generate_iv(length: int) -> bytes:
    """Generate cryptographically secure random IV."""
    return secrets.token_bytes(length)


def secure_zero(data: bytearray) -> None:
    """Securely zero out memory."""
    if data:
        for i in range(len(data)):
            data[i] = 0


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences."""
    return bytes(x ^ y for x, y in zip(a, b))