# secure_rpl.py
"""Secure RPL implementation with hop‑by‑hop ChaCha20‑Poly1305 encryption,
replay‑attack protection, trust‑based parent selection, and key revocation.

This module builds on the minimal baseline implementation provided in `rpl_baseline.py`.
It defines a `SecureRPLNode` class that can be used in simulations.
"""

import os
import struct
import secrets
from typing import Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# Import baseline classes
from rpl_baseline import RPLNode, Packet

# Constants
NONCE_SIZE = 12  # ChaCha20‑Poly1305 nonce size
KEY_SIZE = 32    # 256‑bit key

class SecurePacket(Packet):
    """Packet format used by SecureRPLNode.
    The payload is encrypted; the packet also carries a sequence number.
    """
    def __init__(self, src: int, dst: int, payload: bytes, seq: int, nonce: bytes, tag: bytes):
        super().__init__(src, dst, payload, seq)
        self.nonce = nonce
        self.tag = tag

    def serialize(self) -> bytes:
        """Serialize the packet for transmission.
        Layout (all integers are 4‑byte big‑endian):
        src | dst | seq | nonce_len | nonce | tag_len | tag | ciphertext_len | ciphertext
        """
        parts = []
        parts.append(struct.pack('>I', self.src))
        parts.append(struct.pack('>I', self.dst))
        parts.append(struct.pack('>I', self.seq))
        parts.append(struct.pack('>I', len(self.nonce)))
        parts.append(self.nonce)
        parts.append(struct.pack('>I', len(self.tag)))
        parts.append(self.tag)
        parts.append(struct.pack('>I', len(self.payload)))
        parts.append(self.payload)
        return b''.join(parts)

    @staticmethod
    def deserialize(data: bytes) -> "SecurePacket":
        offset = 0
        src = struct.unpack_from('>I', data, offset)[0]; offset += 4
        dst = struct.unpack_from('>I', data, offset)[0]; offset += 4
        seq = struct.unpack_from('>I', data, offset)[0]; offset += 4
        nonce_len = struct.unpack_from('>I', data, offset)[0]; offset += 4
        nonce = data[offset:offset+nonce_len]; offset += nonce_len
        tag_len = struct.unpack_from('>I', data, offset)[0]; offset += 4
        tag = data[offset:offset+tag_len]; offset += tag_len
        ct_len = struct.unpack_from('>I', data, offset)[0]; offset += 4
        ciphertext = data[offset:offset+ct_len]
        return SecurePacket(src, dst, ciphertext, seq, nonce, tag)

class SecureRPLNode(RPLNode):
    """Secure RPL node extending the baseline node.
    Features:
    * Hop‑by‑hop encryption using ChaCha20‑Poly1305.
    * Replay‑attack detection via per‑sender sequence numbers.
    * Trust‑based parent selection (trust score influences choice).
    * Key revocation support.
    """
    def __init__(self, node_id: int, rank: Optional[float] = None):
        super().__init__(node_id, rank)
        self.neighbor_keys: Dict[int, bytes] = {}
        self.trust_scores: Dict[int, float] = {}
        self.latest_seq: Dict[int, int] = {}
        self._local_seq: int = 0

    # -----------------------------------------------------------------
    # Key management
    # -----------------------------------------------------------------
    def _derive_key_for(self, neighbor_id: int) -> bytes:
        """Derive or retrieve a symmetric key for a neighbor.
        Here we lazily generate a random key per neighbor.
        """
        if neighbor_id not in self.neighbor_keys:
            self.neighbor_keys[neighbor_id] = secrets.token_bytes(KEY_SIZE)
        return self.neighbor_keys[neighbor_id]

    def revoke_key(self, neighbor_id: int) -> None:
        """Revoke the encryption key for a compromised neighbor.
        The neighbor is also removed from the neighbor list.
        """
        self.neighbor_keys.pop(neighbor_id, None)
        self.trust_scores.pop(neighbor_id, None)
        self.latest_seq.pop(neighbor_id, None)
        self.neighbors = [n for n in self.neighbors if n.node_id != neighbor_id]

    # -----------------------------------------------------------------
    # Trust handling
    # -----------------------------------------------------------------
    def set_trust(self, neighbor_id: int, score: float) -> None:
        self.trust_scores[neighbor_id] = max(0.0, score)

    # -----------------------------------------------------------------
    # Encryption / decryption helpers
    # -----------------------------------------------------------------
    def _encrypt_for(self, neighbor_id: int, plaintext: bytes, seq: int) -> Tuple[bytes, bytes, bytes]:
        key = self._derive_key_for(neighbor_id)
        aead = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(NONCE_SIZE)
        aad = struct.pack('>III', self.node_id, neighbor_id, seq)
        ciphertext = aead.encrypt(nonce, plaintext, aad)
        tag = ciphertext[-16:]
        ct = ciphertext[:-16]
        return ct, nonce, tag

    def _decrypt_from(self, neighbor_id: int, ct: bytes, nonce: bytes, tag: bytes, seq: int, src: int) -> bytes:
        key = self._derive_key_for(neighbor_id)
        aead = ChaCha20Poly1305(key)
        aad = struct.pack('>III', src, self.node_id, seq)
        return aead.decrypt(nonce, ct + tag, aad)

    # -----------------------------------------------------------------
    # Sending packets
    # -----------------------------------------------------------------
    def send(self, dst: int, payload: bytes) -> None:
        if self.parent is None:
            self.select_parent()
        if not self.parent:
            raise RuntimeError("No parent to send the packet to")
        self._local_seq += 1
        seq = self._local_seq
        ct, nonce, tag = self._encrypt_for(self.parent.node_id, payload, seq)
        sp = SecurePacket(self.node_id, dst, ct, seq, nonce, tag)
        self.parent.receive_secure(sp)

    # -----------------------------------------------------------------
    # Receiving packets
    # -----------------------------------------------------------------
    def receive_secure(self, packet: SecurePacket) -> None:
        # Replay protection
        last_seq = self.latest_seq.get(packet.src, -1)
        if packet.seq <= last_seq:
            return
        self.latest_seq[packet.src] = packet.seq
        try:
            plaintext = self._decrypt_from(packet.src, packet.payload, packet.nonce, packet.tag, packet.seq, packet.src)
        except Exception:
            return
        if packet.dst == self.node_id:
            self._process_payload(plaintext)
        else:
            if self.parent is None:
                self.select_parent()
            if not self.parent:
                return
            self._local_seq += 1
            next_seq = self._local_seq
            ct, nonce, tag = self._encrypt_for(self.parent.node_id, plaintext, next_seq)
            fwd = SecurePacket(self.node_id, packet.dst, ct, next_seq, nonce, tag)
            self.parent.receive_secure(fwd)

    # -----------------------------------------------------------------
    # Trust‑aware parent selection
    # -----------------------------------------------------------------
    def select_parent(self) -> None:
        if not self.neighbors:
            self.parent = None
            return
        def score(neighbor: "RPLNode") -> float:
            trust = self.trust_scores.get(neighbor.node_id, 1.0)
            return neighbor.rank / (trust + 1e-6)
        self.parent = min(self.neighbors, key=score)

    # -----------------------------------------------------------------
    # Utility (for testing / experiments)
    # -----------------------------------------------------------------
    def dump_state(self) -> dict:
        return {
            "node_id": self.node_id,
            "parent_id": self.parent.node_id if self.parent else None,
            "trust_scores": self.trust_scores,
            "latest_seq": self.latest_seq,
            "neighbor_keys": {nid: key.hex() for nid, key in self.neighbor_keys.items()},
        }

if __name__ == "__main__":
    a = SecureRPLNode(1)
    b = SecureRPLNode(2)
    c = SecureRPLNode(3)
    a.add_neighbor(b)
    b.add_neighbor(c)
    a.set_trust(b.node_id, 0.9)
    b.set_trust(a.node_id, 0.8)
    b.set_trust(c.node_id, 0.7)
    c.set_trust(b.node_id, 0.85)
    a.select_parent(); b.select_parent(); c.select_parent()
    print("Parents:", a.parent, b.parent, c.parent)
    a.send(dst=3, payload=b"Hello Secure RPL")
    print("Simulation finished.")
