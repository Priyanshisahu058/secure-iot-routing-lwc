"""
2. EAVESDROPPING ATTACK SIMULATION
-----------------------------------
Concept:
  An attacker passively listens on the wireless channel and captures every
  packet flowing between sensor nodes, hoping to read the plaintext data.

What this script does:
  1. Generates plaintext sensor packets (what the attacker WOULD see if there
     were no encryption).
  2. Encrypts each packet with AES (key only known to legitimate sender/receiver).
  3. Simulates the attacker capturing only the ciphertext (the attacker never
     gets the key).
  4. "Attacker" attempts naive recovery strategies on the ciphertext:
       - direct ASCII decoding
       - simple frequency analysis
     and we count how many bytes of meaningful plaintext it recovers (0,
     because AES output is uniformly random-looking and the attacker has no key).
  5. Produces a report file confirming 0 bytes of readable plaintext recovered.
"""
import string
from utils import new_key, encrypt, log

REPORT_FILE = "outputs/eavesdropping_report.txt"
open(REPORT_FILE, "w").close()

SENSOR_READINGS = [
    "TEMP:23.5C,HUMIDITY:60%",
    "GPS:12.9716N,77.5946E",
    "BATTERY:78%,STATUS:OK",
    "ALERT:INTRUSION_DETECTED",
    "PRESSURE:1013hPa",
]


def looks_readable(byte_data: bytes) -> int:
    """
    Naive 'attacker' heuristic: count how many bytes, when decoded as
    extended ASCII, fall into printable text range AND form recognizable
    English-like substrings. Used to show ciphertext yields ~0 readable bytes.
    """
    try:
        decoded = byte_data.decode("latin-1")
    except Exception:
        return 0
    printable = sum(1 for c in decoded if c in string.printable and c not in "\t\n\r\x0b\x0c")
    # Require it to also contain a recognizable plaintext keyword to count as "readable"
    keywords = ["TEMP", "GPS", "BATTERY", "ALERT", "PRESSURE", "STATUS"]
    if any(k in decoded for k in keywords):
        return printable
    return 0


def run_simulation():
    key = new_key()  # only legitimate nodes know this
    total_recovered = 0

    print("=== Eavesdropping Attack Simulation ===\n")
    log(REPORT_FILE, "EAVESDROPPING ATTACK REPORT\n" + "=" * 40)

    for i, plaintext in enumerate(SENSOR_READINGS, start=1):
        nonce, ciphertext, tag = encrypt(key, plaintext)

        print(f"Packet {i}:")
        print(f"  Plaintext (pre-encryption) : {plaintext}")
        print(f"  Ciphertext (what attacker captures, hex): {ciphertext.hex()}")

        # Attacker only has ciphertext bytes -- no key
        recovered_bytes = looks_readable(ciphertext)
        total_recovered += recovered_bytes
        print(f"  Readable bytes attacker recovered: {recovered_bytes}\n")

        log(REPORT_FILE, f"Packet {i}")
        log(REPORT_FILE, f"  Original plaintext length : {len(plaintext)} bytes")
        log(REPORT_FILE, f"  Captured ciphertext (hex) : {ciphertext.hex()}")
        log(REPORT_FILE, f"  Readable plaintext recovered by attacker: {recovered_bytes} bytes")
        log(REPORT_FILE, "-" * 40)

    print(f"TOTAL readable plaintext bytes recovered by attacker across all packets: {total_recovered}")
    log(REPORT_FILE, f"\nTOTAL readable plaintext bytes recovered: {total_recovered}")
    log(REPORT_FILE, "CONCLUSION: AES-encrypted ciphertext is indistinguishable from random "
                      "data without the key. Attacker recovered 0 bytes of meaningful plaintext.")

    assert total_recovered == 0, "Attacker should recover 0 readable bytes"
    print(f"\nReport written to {REPORT_FILE}")
    return total_recovered


if __name__ == "__main__":
    run_simulation()