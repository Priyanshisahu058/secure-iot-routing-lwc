"""
crypto.py — Week 03: Lightweight Cryptography for IoT/RPL Networks
Implements ChaCha20-Poly1305 encryption, MAC generation, hop-by-hop
encryption integration, key management with HKDF-based refresh, and
performance benchmarking across five lightweight algorithms.
"""

import os
import time
import hmac
import hashlib
import struct
import statistics
from dataclasses import dataclass, field
from typing import Optional

from Crypto.Cipher import ChaCha20_Poly1305, AES
from Crypto.Hash import CMAC, HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CHACHA_KEY_SIZE   = 32   # bytes (256-bit)
CHACHA_NONCE_SIZE = 12   # bytes (96-bit)
AES_KEY_SIZE      = 16   # bytes (128-bit for AES-CCM)
MAC_KEY_SIZE      = 32   # bytes
TAG_SIZE          = 16   # bytes (Poly1305 / CCM tag)
KEY_REFRESH_EVERY = 100  # packets between key refreshes


# ===========================================================================
# Section 1 – Core Cryptographic Primitives (ChaCha20-Poly1305)
# ===========================================================================

def encrypt(payload: bytes, key: bytes) -> dict:
    """
    Encrypt *payload* with ChaCha20-Poly1305 using *key* (32 bytes).

    Returns a dict with:
        nonce      – 12-byte random nonce
        ciphertext – encrypted bytes
        tag        – 16-byte Poly1305 authentication tag
    """
    if len(key) != CHACHA_KEY_SIZE:
        raise ValueError(f"Key must be {CHACHA_KEY_SIZE} bytes, got {len(key)}")

    nonce  = get_random_bytes(CHACHA_NONCE_SIZE)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(payload)

    return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}


def decrypt(ciphertext_bundle: dict, key: bytes) -> bytes:
    """
    Decrypt a bundle produced by :func:`encrypt`.

    Raises ``ValueError`` on authentication failure (tampered data).
    """
    if len(key) != CHACHA_KEY_SIZE:
        raise ValueError(f"Key must be {CHACHA_KEY_SIZE} bytes, got {len(key)}")

    nonce      = ciphertext_bundle["nonce"]
    ciphertext = ciphertext_bundle["ciphertext"]
    tag        = ciphertext_bundle["tag"]

    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("MAC verification failed — packet may have been tampered with.")

    return plaintext


def generate_mac(msg: bytes, key: bytes) -> bytes:
    """
    Generate a 32-byte HMAC-SHA256 Message Authentication Code for *msg*.

    The MAC can be transmitted alongside the encrypted packet so that
    each hop can verify authenticity before forwarding.
    """
    h = HMAC.new(key, msg=msg, digestmod=SHA256)
    return h.digest()


def verify_mac(msg: bytes, key: bytes, mac: bytes) -> bool:
    """Return True if *mac* matches the expected MAC for *msg*."""
    expected = generate_mac(msg, key)
    return hmac.compare_digest(expected, mac)


# ===========================================================================
# Section 2 – Hop-by-Hop Encryption (RPL Integration)
# ===========================================================================

@dataclass
class RPLPacket:
    """Represents an in-flight RPL data packet."""
    payload:    bytes
    src_id:     str
    dst_id:     str
    hop_count:  int = 0
    bundle:     Optional[dict]  = None   # encrypted bundle
    mac:        Optional[bytes] = None   # over ciphertext
    path:       list = field(default_factory=list)


def hop_encrypt(packet: RPLPacket, enc_key: bytes, mac_key: bytes) -> RPLPacket:
    """
    Encrypt *packet* for the next hop and attach a MAC.

    Called by a node before forwarding the packet.
    """
    bundle      = encrypt(packet.payload, enc_key)
    mac         = generate_mac(bundle["ciphertext"], mac_key)
    packet.bundle     = bundle
    packet.mac        = mac
    packet.hop_count += 1
    packet.path.append(f"encrypted_by_{packet.src_id}")
    return packet


def hop_decrypt_and_forward(
    packet: RPLPacket,
    node_id: str,
    dec_key: bytes,
    mac_key: bytes,
    next_enc_key: bytes,
    next_mac_key: bytes,
) -> RPLPacket:
    """
    Intermediate-node processing:
      1. Verify MAC  → reject if invalid
      2. Decrypt the ciphertext
      3. Re-encrypt with the key shared with the NEXT hop
      4. Attach a fresh MAC
      5. Forward (return updated packet)
    """
    # Step 1 — verify MAC
    if not verify_mac(packet.bundle["ciphertext"], mac_key, packet.mac):
        raise ValueError(f"Node {node_id}: MAC verification failed. Dropping packet.")

    # Step 2 — decrypt
    plaintext = decrypt(packet.bundle, dec_key)
    packet.payload = plaintext
    packet.path.append(f"decrypted_at_{node_id}")

    # Step 3 & 4 — re-encrypt for next hop and new MAC
    new_bundle = encrypt(plaintext, next_enc_key)
    new_mac    = generate_mac(new_bundle["ciphertext"], next_mac_key)

    packet.bundle     = new_bundle
    packet.mac        = new_mac
    packet.hop_count += 1
    packet.path.append(f"re-encrypted_at_{node_id}")

    return packet


def hop_final_decrypt(
    packet: RPLPacket,
    node_id: str,
    dec_key: bytes,
    mac_key: bytes,
) -> bytes:
    """
    Destination-node processing:
      1. Verify MAC
      2. Decrypt and return plaintext
    """
    if not verify_mac(packet.bundle["ciphertext"], mac_key, packet.mac):
        raise ValueError(f"Destination {node_id}: MAC verification failed.")

    plaintext = decrypt(packet.bundle, dec_key)
    packet.path.append(f"delivered_at_{node_id}")
    return plaintext


# ===========================================================================
# Section 3 – Key Management Module
# ===========================================================================

class KeyManager:
    """
    Manages pre-shared keys and session-key refresh for a single node pair.

    Pre-shared keys are assigned at network deployment.  After every
    KEY_REFRESH_EVERY packets a new session key is derived via HKDF
    (HMAC-based Key Derivation Function).
    """

    def __init__(self, psk: bytes, node_id: str = "node", refresh_every: int = KEY_REFRESH_EVERY):
        if len(psk) < 16:
            raise ValueError("Pre-shared key must be at least 16 bytes.")
        self.node_id       = node_id
        self.psk           = psk
        self.refresh_every = refresh_every
        self.packet_count  = 0
        self.session_key   = self._derive_session_key(epoch=0)
        self.epoch         = 0

    # ------------------------------------------------------------------
    def _derive_session_key(self, epoch: int) -> bytes:
        """Derive a 32-byte session key from the PSK and the current epoch."""
        salt = struct.pack(">Q", epoch)          # 8-byte big-endian epoch
        key  = HKDF(
            master   = self.psk,
            key_len  = CHACHA_KEY_SIZE,
            salt     = salt,
            hashmod  = SHA256,
            num_keys = 1,
        )
        return key

    # ------------------------------------------------------------------
    def get_key(self) -> bytes:
        """Return the current session key, refreshing if needed."""
        self.packet_count += 1
        if self.packet_count % self.refresh_every == 0:
            self.refresh_key()
        return self.session_key

    def refresh_key(self):
        """Derive and install a new session key for the next epoch."""
        self.epoch       += 1
        self.session_key  = self._derive_session_key(self.epoch)
        print(f"[KeyManager:{self.node_id}] Key refreshed → epoch {self.epoch}")

    # ------------------------------------------------------------------
    @staticmethod
    def generate_psk() -> bytes:
        """Generate a cryptographically random 32-byte pre-shared key."""
        return get_random_bytes(CHACHA_KEY_SIZE)

    @staticmethod
    def assign_network_keys(node_ids: list[str]) -> dict[str, bytes]:
        """
        Assign a unique PSK to every node at network deployment time.

        Returns a dict mapping node_id → PSK (bytes).
        """
        return {node_id: get_random_bytes(CHACHA_KEY_SIZE) for node_id in node_ids}


# ===========================================================================
# Section 4 – Benchmark Suite (5 Algorithms)
# ===========================================================================

# ---- Pure-Python PRESENT-80 (80-bit key, 64-bit block) -------------------

_PRESENT_SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
                 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
_PRESENT_SBOX_INV = [_PRESENT_SBOX.index(i) for i in range(16)]

def _present_permute(state: int) -> int:
    out = 0
    for i in range(64):
        bit = (state >> i) & 1
        out |= bit << (16 * (i % 4) + (i // 4))
    return out

def _present_key_schedule(key80: int):
    subkeys = []
    for _ in range(32):
        subkeys.append(key80 >> 16)
        key80 = (((key80 << 61) | (key80 >> 19)) & 0xFFFFFFFFFFFFFFFFFFFF)
        top4  = key80 >> 76
        key80  = (key80 & ~(0xF << 76)) | (_PRESENT_SBOX[top4] << 76)
    subkeys.append(key80 >> 16)
    return subkeys

def _present_encrypt_block(block: int, subkeys: list) -> int:
    state = block
    for r in range(31):
        state ^= subkeys[r]
        tmp    = 0
        for i in range(16):
            nibble = (state >> (4 * i)) & 0xF
            tmp   |= _PRESENT_SBOX[nibble] << (4 * i)
        state = _present_permute(tmp)
    state ^= subkeys[31]
    return state

def _present_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt *data* with PRESENT-80 in ECB mode (benchmark only)."""
    if len(key) < 10:
        key = key[:10].ljust(10, b'\x00')
    k80 = int.from_bytes(key[:10], 'big')
    subkeys = _present_key_schedule(k80)
    # pad to multiple of 8 bytes
    pad = (8 - len(data) % 8) % 8
    data += bytes([pad] * (pad or 8))
    out  = b''
    for i in range(0, len(data), 8):
        blk = int.from_bytes(data[i:i+8], 'big')
        out += _present_encrypt_block(blk, subkeys).to_bytes(8, 'big')
    return out

# ---- Pure-Python SIMON-64/128 --------------------------------------------

def _simon_encrypt_block(x: int, y: int, key_words: list) -> tuple:
    for k in key_words:
        t = x
        x = y ^ (((x << 1) | (x >> 31)) & 0xFFFFFFFF) & \
                 (((x << 8) | (x >> 24)) & 0xFFFFFFFF) ^ \
                 ((x << 2) | (x >> 30)) & 0xFFFFFFFF ^ k
        y = t
    return x, y

def _simon_key_expand(key128: bytes, rounds: int = 44):
    words = [int.from_bytes(key128[i:i+4], 'little') for i in range(0, 16, 4)]
    ks    = list(words)
    c     = 0xFFFFFFFC
    z     = 0b10001101101011010100100000111011101111101110100101110001001011000
    for i in range(4, rounds):
        tmp = ((ks[-1] >> 3) | (ks[-1] << 29)) & 0xFFFFFFFF
        tmp ^= ks[-3]
        tmp ^= (tmp >> 1) | (tmp << 31) & 0xFFFFFFFF
        bit  = (z >> (i % 62)) & 1
        tmp ^= c ^ bit ^ ks[i - 4]
        ks.append(tmp & 0xFFFFFFFF)
    return ks

def _simon_encrypt(data: bytes, key: bytes) -> bytes:
    key16 = (key + b'\x00' * 16)[:16]
    ks    = _simon_key_expand(key16)
    pad   = (8 - len(data) % 8) % 8
    data += bytes([pad] * (pad or 8))
    out   = b''
    for i in range(0, len(data), 8):
        x = int.from_bytes(data[i:i+4], 'little')
        y = int.from_bytes(data[i+4:i+8], 'little')
        x, y = _simon_encrypt_block(x, y, ks)
        out  += x.to_bytes(4, 'little') + y.to_bytes(4, 'little')
    return out

# ---- Pure-Python SPECK-64/128 --------------------------------------------

def _speck_key_expand(key128: bytes, rounds: int = 27):
    words = [int.from_bytes(key128[i:i+4], 'little') for i in range(0, 16, 4)]
    b, a  = words[0], words[1:]
    ks    = [b]
    for i in range(rounds - 1):
        a[0] = (((a[0] >> 8) | (a[0] << 24)) + b) & 0xFFFFFFFF ^ i
        b    = ((b << 3) | (b >> 29)) & 0xFFFFFFFF ^ a[0]
        a.append(a.pop(0))
        ks.append(b)
    return ks

def _speck_encrypt(data: bytes, key: bytes) -> bytes:
    key16 = (key + b'\x00' * 16)[:16]
    ks    = _speck_key_expand(key16)
    pad   = (8 - len(data) % 8) % 8
    data += bytes([pad] * (pad or 8))
    out   = b''
    for i in range(0, len(data), 8):
        x = int.from_bytes(data[i:i+4], 'little')
        y = int.from_bytes(data[i+4:i+8], 'little')
        for k in ks:
            x = ((x >> 8) | (x << 24)) & 0xFFFFFFFF
            x = (x + y) & 0xFFFFFFFF ^ k
            y = ((y << 3) | (y >> 29)) & 0xFFFFFFFF ^ x
        out += x.to_bytes(4, 'little') + y.to_bytes(4, 'little')
    return out

# ---- AES-CCM (via PyCryptodome) ------------------------------------------

def _aes_ccm_encrypt(data: bytes, key: bytes) -> bytes:
    key16  = (key + b'\x00' * 16)[:16]
    nonce  = get_random_bytes(11)
    cipher = AES.new(key16, AES.MODE_CCM, nonce=nonce, mac_len=TAG_SIZE)
    ct, tag = cipher.encrypt_and_digest(data)
    return nonce + ct + tag

def _aes_ccm_decrypt(bundle: bytes, key: bytes) -> bytes:
    key16  = (key + b'\x00' * 16)[:16]
    nonce  = bundle[:11]
    ct     = bundle[11:-TAG_SIZE]
    tag    = bundle[-TAG_SIZE:]
    cipher = AES.new(key16, AES.MODE_CCM, nonce=nonce, mac_len=TAG_SIZE)
    return cipher.decrypt_and_verify(ct, tag)

# ---- ChaCha20-Poly1305 (already implemented above) -----------------------

def _chacha_encrypt_raw(data: bytes, key: bytes) -> bytes:
    bundle = encrypt(data, key)
    return bundle["nonce"] + bundle["ciphertext"] + bundle["tag"]

def _chacha_decrypt_raw(bundle: bytes, key: bytes) -> bytes:
    nonce  = bundle[:CHACHA_NONCE_SIZE]
    ct     = bundle[CHACHA_NONCE_SIZE:-TAG_SIZE]
    tag    = bundle[-TAG_SIZE:]
    return decrypt({"nonce": nonce, "ciphertext": ct, "tag": tag}, key)

# --------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    algorithm:       str
    enc_times_us:    list[float]
    dec_times_us:    list[float]
    energy_enc_mj:   list[float]
    energy_dec_mj:   list[float]

    # Assumes a typical Cortex-M0+ IoT node:
    #   • Active current ~10 mA @ 3.3 V → 33 mW
    POWER_W = 0.033

    @property
    def avg_enc_us(self):  return statistics.mean(self.enc_times_us)
    @property
    def avg_dec_us(self):  return statistics.mean(self.dec_times_us)
    @property
    def avg_energy_enc_mj(self): return statistics.mean(self.energy_enc_mj)
    @property
    def avg_energy_dec_mj(self): return statistics.mean(self.energy_dec_mj)

    def summary(self) -> str:
        return (
            f"  Enc: {self.avg_enc_us:8.1f} µs | "
            f"Dec: {self.avg_dec_us:8.1f} µs | "
            f"E_enc: {self.avg_energy_enc_mj:.4f} mJ | "
            f"E_dec: {self.avg_energy_dec_mj:.4f} mJ"
        )


def benchmark_algorithms(
    payload: bytes = b"Hello RPL IoT world! " * 4,
    iterations: int = 200,
) -> list[BenchmarkResult]:
    """
    Benchmark all five algorithms on *payload* for *iterations* rounds.

    Algorithms tested: PRESENT-80, SIMON-64/128, SPECK-64/128,
                       ChaCha20-Poly1305, AES-CCM.
    Returns a list of :class:`BenchmarkResult`.
    """

    key32 = get_random_bytes(32)
    key16 = key32[:16]
    key10 = key32[:10]

    POWER_W = BenchmarkResult.POWER_W  # 33 mW

    results: list[BenchmarkResult] = []

    configs = [
        ("PRESENT-80",
         lambda d: _present_encrypt(d, key10),
         lambda ct: ct,  # no decrypt impl needed for benchmark
         False),
        ("SIMON-64/128",
         lambda d: _simon_encrypt(d, key16),
         lambda ct: ct,
         False),
        ("SPECK-64/128",
         lambda d: _speck_encrypt(d, key16),
         lambda ct: ct,
         False),
        ("ChaCha20-Poly1305",
         lambda d: _chacha_encrypt_raw(d, key32),
         lambda ct: _chacha_decrypt_raw(ct, key32),
         True),
        ("AES-CCM",
         lambda d: _aes_ccm_encrypt(d, key16),
         lambda ct: _aes_ccm_decrypt(ct, key16),
         True),
    ]

    for name, enc_fn, dec_fn, has_dec in configs:
        enc_times, dec_times = [], []
        energy_enc, energy_dec = [], []

        for _ in range(iterations):
            t0 = time.perf_counter()
            ct = enc_fn(payload)
            t1 = time.perf_counter()

            enc_us = (t1 - t0) * 1e6
            enc_mj = POWER_W * (t1 - t0) * 1e3

            enc_times.append(enc_us)
            energy_enc.append(enc_mj)

            if has_dec:
                t2 = time.perf_counter()
                dec_fn(ct)
                t3 = time.perf_counter()
                dec_us = (t3 - t2) * 1e6
                dec_mj = POWER_W * (t3 - t2) * 1e3
            else:
                # symmetric cipher — use enc time as proxy for dec
                dec_us = enc_us
                dec_mj = enc_mj

            dec_times.append(dec_us)
            energy_dec.append(dec_mj)

        results.append(BenchmarkResult(
            algorithm     = name,
            enc_times_us  = enc_times,
            dec_times_us  = dec_times,
            energy_enc_mj = energy_enc,
            energy_dec_mj = energy_dec,
        ))

    return results


def print_benchmark_report(results: list[BenchmarkResult]):
    """Print a formatted benchmark report to stdout."""
    header = f"\n{'='*72}\n  ENCRYPTION BENCHMARK REPORT\n{'='*72}"
    print(header)
    print(f"  {'Algorithm':<22} {'Enc (µs)':>10} {'Dec (µs)':>10} "
          f"{'E_enc (mJ)':>12} {'E_dec (mJ)':>12}")
    print(f"  {'-'*22} {'-'*10} {'-'*10} {'-'*12} {'-'*12}")

    best_enc = min(results, key=lambda r: r.avg_enc_us)
    best_nrg = min(results, key=lambda r: r.avg_energy_enc_mj)

    for r in results:
        flag = ""
        if r.algorithm == best_enc.algorithm: flag += " ← fastest"
        if r.algorithm == best_nrg.algorithm and r.algorithm != best_enc.algorithm:
            flag += " ← lowest energy"
        print(f"  {r.algorithm:<22} {r.avg_enc_us:>10.1f} {r.avg_dec_us:>10.1f} "
              f"{r.avg_energy_enc_mj:>12.5f} {r.avg_energy_dec_mj:>12.5f}{flag}")

    print(f"\n  Best overall encryption speed : {best_enc.algorithm}")
    print(f"  Lowest energy consumption    : {best_nrg.algorithm}")
    print('='*72)


# ===========================================================================
# Section 5 – Demo / Self-test
# ===========================================================================

def _demo_core_primitives():
    print("\n── Core Primitives ─────────────────────────────────────────────")
    key     = get_random_bytes(CHACHA_KEY_SIZE)
    mac_key = get_random_bytes(MAC_KEY_SIZE)
    msg     = b"Sensor reading: temp=22.5C, hum=60%"

    bundle  = encrypt(msg, key)
    print(f"  Encrypted  : {bundle['ciphertext'].hex()[:40]}…")
    recovered = decrypt(bundle, key)
    print(f"  Decrypted  : {recovered}")

    mac = generate_mac(msg, mac_key)
    print(f"  MAC (hex)  : {mac.hex()}")
    ok  = verify_mac(msg, mac_key, mac)
    print(f"  MAC valid  : {ok}")

    # tamper test
    tampered = bytearray(bundle["ciphertext"]); tampered[0] ^= 0xFF
    bundle_bad = {**bundle, "ciphertext": bytes(tampered)}
    try:
        decrypt(bundle_bad, key)
    except ValueError as e:
        print(f"  Tamper det.: ✓ ({e})")


def _demo_hop_by_hop():
    print("\n── Hop-by-Hop Encryption ───────────────────────────────────────")
    # Topology: src → nodeA → nodeB → dst
    # Each link has its own key pair (enc, mac)
    keys = {link: (get_random_bytes(32), get_random_bytes(32))
            for link in ["src-A", "A-B", "B-dst"]}

    payload = b"RPL payload: route_via=A,B dest=sink"
    pkt = RPLPacket(payload=payload, src_id="src", dst_id="dst")

    # Source encrypts for link src→A
    enc_key, mac_key = keys["src-A"]
    pkt = hop_encrypt(pkt, enc_key, mac_key)
    print(f"  After src  : hop={pkt.hop_count}, path={pkt.path}")

    # Node A: decrypt from src, re-encrypt for B
    pkt = hop_decrypt_and_forward(
        pkt, "nodeA",
        dec_key=keys["src-A"][0], mac_key=keys["src-A"][1],
        next_enc_key=keys["A-B"][0], next_mac_key=keys["A-B"][1],
    )
    print(f"  After nodeA: hop={pkt.hop_count}")

    # Node B: decrypt from A, re-encrypt for dst
    pkt = hop_decrypt_and_forward(
        pkt, "nodeB",
        dec_key=keys["A-B"][0], mac_key=keys["A-B"][1],
        next_enc_key=keys["B-dst"][0], next_mac_key=keys["B-dst"][1],
    )
    print(f"  After nodeB: hop={pkt.hop_count}")

    # Destination decrypts
    result = hop_final_decrypt(
        pkt, "dst",
        dec_key=keys["B-dst"][0], mac_key=keys["B-dst"][1],
    )
    assert result == payload
    print(f"  Delivered  : {result}")
    print(f"  Full path  : {pkt.path}")


def _demo_key_management():
    print("\n── Key Management ──────────────────────────────────────────────")
    # Assign keys to a small network
    nodes = ["node_1", "node_2", "node_3", "sink"]
    network_keys = KeyManager.assign_network_keys(nodes)
    print(f"  Deployed PSKs for: {list(network_keys.keys())}")

    km = KeyManager(network_keys["node_1"], node_id="node_1", refresh_every=5)
    for i in range(12):
        k = km.get_key()
    print(f"  Current epoch after 12 packets: {km.epoch}")


if __name__ == "__main__":
    _demo_core_primitives()
    _demo_hop_by_hop()
    _demo_key_management()

    print("\n── Benchmark (200 iterations × 5 algorithms) ───────────────────")
    results = benchmark_algorithms(iterations=200)
    print_benchmark_report(results)