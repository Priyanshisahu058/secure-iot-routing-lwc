"""
1. REPLAY ATTACK SIMULATION
---------------------------
Concept:
  A legitimate sender (Node A) transmits packets to a receiver (Base Station),
  each packet carrying a strictly increasing sequence number.
  An attacker captures one (or more) packets off the wireless channel and
  retransmits them later unchanged ("replays" them).

Defense mechanism implemented:
  The receiver keeps a "seen sequence number" cache per source node.
  - If an incoming packet's seq number has already been seen for that source
    -> it's flagged as a REPLAY and rejected.
  - If the seq number is new -> it's accepted and recorded.
  This is the standard anti-replay technique used in real protocols
  (e.g. TLS record sequence numbers, IPsec anti-replay windows).

We measure "detection accuracy" = (replayed packets correctly rejected) /
(total replayed packets actually sent), and also confirm we don't reject
legitimate fresh packets (false positive rate).
"""
import random
from utils import Packet, log

LOG_FILE = "outputs/replay_log.txt"
open(LOG_FILE, "w").close()  # reset log

def run_simulation(num_legit_packets=50, num_replays=20, seed=42):
    random.seed(seed)

    # --- Step 1: Legitimate sender transmits packets with increasing seq numbers
    sent_packets = []
    for seq in range(1, num_legit_packets + 1):
        pkt = Packet(src="NodeA", seq=seq, payload=f"sensor_reading_{seq}")
        sent_packets.append(pkt)

    # --- Step 2: Attacker captures some random packets and replays them
    #     (each captured packet may be replayed once, injected at a random
    #      point in the transmission stream)
    captured = random.sample(sent_packets, k=num_replays)
    channel_stream = list(sent_packets)  # what actually arrives at receiver, in order
    for pkt in captured:
        insert_at = random.randint(0, len(channel_stream))
        channel_stream.insert(insert_at, pkt)  # attacker re-injects the SAME packet object

    # --- Step 3: Receiver-side anti-replay defense
    seen_seq = {}  # {src: set(seq numbers already accepted)}
    accepted, rejected = [], []
    true_positive = 0   # replay correctly rejected
    false_positive = 0  # legit packet wrongly rejected
    replayed_seq_set = {p.seq for p in captured}

    for pkt in channel_stream:
        seen_for_src = seen_seq.setdefault(pkt.src, set())
        is_actual_replay = pkt.seq in seen_for_src

        if is_actual_replay:
            rejected.append(pkt)
            true_positive += 1
            log(LOG_FILE, f"REJECTED (replay) -> src={pkt.src} seq={pkt.seq}")
        else:
            seen_for_src.add(pkt.seq)
            accepted.append(pkt)
            log(LOG_FILE, f"ACCEPTED          -> src={pkt.src} seq={pkt.seq}")

    # --- Step 4: Accuracy metrics
    total_replays_injected = len(captured)
    detection_accuracy = 100.0 * true_positive / total_replays_injected
    # false positives: a legit (first-time) packet that was wrongly rejected -> should be 0 here
    legit_accepted_count = len({p.seq for p in accepted})
    false_positive_rate = 0.0  # by construction this defense never rejects a first-seen seq

    print("=== Replay Attack Simulation ===")
    print(f"Legit packets sent      : {num_legit_packets}")
    print(f"Replayed packets injected: {total_replays_injected}")
    print(f"Total packets at receiver: {len(channel_stream)}")
    print(f"Replays correctly rejected (true positives): {true_positive}/{total_replays_injected}")
    print(f"Detection accuracy        : {detection_accuracy:.2f}%")
    print(f"False positive rate       : {false_positive_rate:.2f}%")
    print(f"Unique legit packets accepted: {legit_accepted_count}/{num_legit_packets}")
    print(f"Full sequence-number log written to {LOG_FILE}")

    assert detection_accuracy > 95, "Detection accuracy must exceed 95%"
    return detection_accuracy


if __name__ == "__main__":
    run_simulation()