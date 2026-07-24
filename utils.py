"""
Shared helpers used by all four attack-simulation scripts.
- Packet: a simple data packet with a sequence number, source, and payload
- AES helpers: encrypt/decrypt using a 128-bit key (pycryptodome, AES-EAX mode)
"""
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


class Packet:
    """A minimal sensor-network packet."""
    def __init__(self, src, seq, payload):
        self.src = src
        self.seq = seq
        self.payload = payload
        self.timestamp = time.time()

    def __repr__(self):
        return f"Packet(src={self.src}, seq={self.seq}, payload={self.payload!r})"


def new_key():
    """Generate a fresh random 128-bit AES key."""
    return get_random_bytes(16)


def encrypt(key, plaintext: str):
    """Encrypt a string. Returns (nonce, ciphertext, tag) all as bytes."""
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce, ciphertext, tag


def decrypt(key, nonce, ciphertext, tag):
    """Decrypt; raises ValueError if key/tag don't match (tamper/wrong key)."""
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode()


def log(path, line):
    with open(path, "a") as f:
        f.write(line + "\n")