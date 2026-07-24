"""
3. NODE CAPTURE ATTACK SIMULATION
-----------------------------------
Concept:
  An attacker physically captures a sensor node and extracts its cryptographic
  key (this is a realistic threat in WSNs since nodes are often deployed in
  unattended, physically accessible locations).

What this script does:
  1. Sets up a small network of nodes, each holding a symmetric key issued by
     a trusted Base Station (key distribution center).
  2. Simulates capture of one node -> its key is now known to the attacker.
  3. Base Station detects the compromise (in real systems via anomaly
     detection / missed heartbeats / out-of-pattern traffic -- here we
     simulate immediate detection once capture is flagged).
  4. Base Station REVOKES the compromised node's key and broadcasts a
     re-keying event: every legitimate (non-captured) node receives a brand
     new key over an authenticated channel.
  5. We simulate several "routing cycles" after revocation and show that
     all legitimate nodes can communicate securely again, while the captured
     node (with its old, revoked key) can no longer decrypt new traffic.
  6. Confirms recovery happens within 5 routing cycles, and writes a recovery log.
"""
from utils import new_key, encrypt, decrypt, log

LOG_FILE = "outputs/node_capture_recovery_log.txt"
open(LOG_FILE, "w").close()


class Node:
    def __init__(self, name, key):
        self.name = name
        self.key = key
        self.compromised = False


def run_simulation():
    node_names = ["N1", "N2", "N3", "N4", "N5"]
    nodes = {name: Node(name, new_key()) for name in node_names}
    captured_node_name = "N3"

    print("=== Node Capture Attack Simulation ===\n")
    log(LOG_FILE, "NODE CAPTURE & RECOVERY LOG")
    log(LOG_FILE, "=" * 40)

    print(f"Step 1: Network established with nodes {node_names}, each with a unique AES key.\n")
    log(LOG_FILE, f"Initial network: {node_names}")

    # --- Step 2: Attacker captures N3, steals its key
    nodes[captured_node_name].compromised = True
    stolen_key = nodes[captured_node_name].key
    print(f"Step 2: Node {captured_node_name} is physically captured. Attacker extracts its key: "
          f"{stolen_key.hex()}\n")
    log(LOG_FILE, f"[CAPTURE] Node {captured_node_name} compromised. Key stolen: {stolen_key.hex()}")

    # Sanity check: attacker can decrypt traffic that used the old key
    msg = "ROUTE_UPDATE:next_hop=BaseStation"
    nonce, ct, tag = encrypt(stolen_key, msg)
    attacker_reads = decrypt(stolen_key, nonce, ct, tag)
    print(f"  -> With the stolen key, attacker CAN decrypt old traffic: '{attacker_reads}'\n")
    log(LOG_FILE, f"  Attacker decrypts pre-revocation traffic successfully: '{attacker_reads}'")

    # --- Step 3: Base Station detects compromise and starts revocation
    print(f"Step 3: Base Station detects anomalous behaviour from {captured_node_name} "
          f"-> flags it as COMPROMISED.\n")
    log(LOG_FILE, f"[DETECTION] Base Station flags {captured_node_name} as compromised.")

    # --- Step 4: Key revocation + re-keying of legitimate nodes
    print("Step 4: Key revocation process:")
    log(LOG_FILE, "[REVOCATION] Revoking key for compromised node and re-keying legitimate nodes.")
    fresh_group_key = new_key()  # Base Station distributes one new shared group key
    for name, node in nodes.items():
        if node.compromised:
            node.key = None  # revoked, node excluded from network
            print(f"  - {name}: key REVOKED. Node removed from trusted routing table.")
            log(LOG_FILE, f"  {name}: key revoked, excluded from network.")
        else:
            old_key = node.key
            node.key = fresh_group_key  # fresh key issued by Base Station, securely distributed
            print(f"  - {name}: issued NEW key {node.key.hex()} (old key {old_key.hex()[:8]}... discarded)")
            log(LOG_FILE, f"  {name}: re-keyed. New key {node.key.hex()}")
    print()

    # --- Step 5: Simulate routing cycles post-revocation, show secure comm resumes
    print("Step 5: Verifying secure communication resumes among legitimate nodes:\n")
    legit_nodes = [n for n in nodes.values() if not n.compromised]
    recovered_cycle = None
    for cycle in range(1, 6):  # simulate up to 5 routing cycles
        sender, receiver = legit_nodes[0], legit_nodes[1]
        test_msg = f"ROUTE_UPDATE:cycle={cycle}"
        nonce, ct, tag = encrypt(sender.key, test_msg)
        try:
            # Receiver shares the same fresh group key in this simple scheme
            plaintext = decrypt(receiver.key, nonce, ct, tag)
            success = (plaintext == test_msg)
        except Exception:
            success = False

        # Confirm captured node's OLD key can no longer decrypt new traffic
        try:
            decrypt(stolen_key, nonce, ct, tag)
            attacker_blocked = False
        except Exception:
            attacker_blocked = True

        status = "SECURE COMMS RESTORED" if success and attacker_blocked else "still recovering"
        print(f"  Routing cycle {cycle}: {sender.name}->{receiver.name} | "
              f"legit decrypt OK={success} | attacker (old key) blocked={attacker_blocked} | {status}")
        log(LOG_FILE, f"[CYCLE {cycle}] legit_decrypt_ok={success} attacker_blocked={attacker_blocked}")

        if success and attacker_blocked and recovered_cycle is None:
            recovered_cycle = cycle

    print(f"\nSecure communication fully resumed at routing cycle: {recovered_cycle}")
    log(LOG_FILE, f"\nRECOVERY COMPLETE at routing cycle {recovered_cycle} (<= 5 required).")
    assert recovered_cycle is not None and recovered_cycle <= 5
    print(f"Recovery log written to {LOG_FILE}")
    return recovered_cycle


if __name__ == "__main__":
    run_simulation()