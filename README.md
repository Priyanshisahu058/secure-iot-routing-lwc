# Secure IoT Routing with Lightweight Cryptography

> **Week 2 Assignment | RVU-CY-SI-26-10**  
> **Author:** Priyanshi Sahu  
> **Repository:** [secure-iot-routing-lwc](https://github.com/Priyanshisahu058/secure-iot-routing-lwc)

---

## Overview

This project implements and evaluates a **Secure RPL (Routing Protocol for Low-Power and Lossy Networks)** for IoT sensor networks. It extends a baseline RPL implementation with four key security features:

| Feature | Mechanism |
|---|---|
| Hop-by-Hop Encryption | ChaCha20-Poly1305 (256-bit key) |
| Replay Attack Prevention | Per-sender sequence number tracking |
| Trust-Based Parent Selection | Trust score × RPL rank combined metric |
| Key Revocation | Immediate removal of compromised node keys |

Simulations are run across **4 network topologies** (Star-50, Mesh-100, Tree-80, Random-150) with **500 UDP packets each**, and compared against baseline RPL under both normal and attack conditions.

---

## Repository Structure

```
secure-iot-routing-lwc/
│
├── network.py                  # IoT node model + 4 topology builders
├── rpl_baseline.py             # Baseline RPL (DODAG, Trickle timer, OF0)
├── secure_rpl.py               # Secure RPL with encryption & trust
├── crypto.py                   # ChaCha20-Poly1305, MAC, HKDF, benchmarks
├── traffic_generator.py        # UDP traffic simulator + PDR/Delay metrics
├── utils.py                    # Shared packet and AES helpers
│
├── replay_attack.py            # Replay attack simulation + detection
├── eavesdropping_attack.py     # Eavesdropping simulation
├── sinkhole_attack.py          # Sinkhole attack + trust-score detection
├── node_capture_atttack.py     # Node capture + key revocation demo
│
├── run_all.py                  # Master runner — executes all experiments
│
├── results/                    # Generated charts and CSVs
│   ├── topology_*.png          # 4 topology diagrams
│   ├── dodag_*.png             # 4 DODAG tree visualizations
│   ├── traffic_summary_chart.png
│   ├── secure_rpl_metrics.png
│   ├── baseline_vs_secure_comparison.png
│   ├── attack_scenario_comparison.png
│   ├── baseline_traffic.csv
│   ├── secure_traffic.csv
│   └── full_summary.csv
│
├── outputs/                    # Attack simulation logs and graphs
│   ├── replay_log.txt
│   ├── eavesdropping_report.txt
│   ├── sinkhole_log.txt
│   ├── trust_scores.png
│   └── node_capture_recovery_log.txt
│
├── .gitignore
└── README.md
```

---

## Setup

### Prerequisites
- Python 3.10+
- MSYS2 / pacman (Windows) **or** pip (Linux/macOS)

### Install Dependencies

**Windows (MSYS2):**
```bash
C:\msys64\usr\bin\pacman.exe -S --noconfirm \
  mingw-w64-ucrt-x86_64-python-matplotlib \
  mingw-w64-ucrt-x86_64-python-networkx \
  mingw-w64-ucrt-x86_64-python-numpy \
  mingw-w64-ucrt-x86_64-python-pycryptodome
```

**Linux / macOS:**
```bash
pip install matplotlib networkx numpy pycryptodome
```

### Run All Experiments
```bash
python -X utf8 run_all.py
```

This single command runs every experiment end-to-end and saves all results to `results/` and `outputs/`.

---

## Network Topologies

| Topology | Nodes | Structure | DODAG |
|---|---|---|---|
| Star-50 | 50 | Hub + 49 leaves, 1-hop | `results/dodag_star_50.png` |
| Mesh-100 | 100 | Grid, multi-hop | `results/dodag_mesh_100.png` |
| Tree-80 | 80 | Balanced binary tree | `results/dodag_tree_80.png` |
| Random-150 | 150 | Random scatter, 50m range | `results/dodag_random_150.png` |

---

## Experiment 1 — Baseline RPL Performance

500 UDP packets injected per topology. Metrics: PDR, delay, hop count.

| Topology | PDR | Avg Delay | Avg Hops | Delivered |
|---|---|---|---|---|
| Star-50 | **97.6%** | 7.02 ms | 1.0 | 488 / 500 |
| Mesh-100 | 82.6% | 33.82 ms | 8.69 | 413 / 500 |
| Tree-80 | 88.6% | 19.64 ms | 4.61 | 443 / 500 |
| Random-150 | 89.4% | 18.69 ms | 4.36 | 447 / 500 |

> Chart: `results/traffic_summary_chart.png`

---

## Experiment 2 — Secure RPL Performance

Same 500 packets per topology with ChaCha20-Poly1305 encryption at every hop,
sequence-number replay protection, and trust-based parent selection.

| Topology | PDR | Avg Delay | Avg Hops | Energy/pkt | Memory/pkt | Delivered |
|---|---|---|---|---|---|---|
| Star-50 | **96.4%** | 7.59 ms | 1.0 | 0.0750 mJ | 0.0156 KB | 482 / 500 |
| Mesh-100 | 80.6% | 37.45 ms | 8.86 | 0.6644 mJ | 0.0770 KB | 403 / 500 |
| Tree-80 | 87.0% | 20.86 ms | 4.48 | 0.3359 mJ | 0.0428 KB | 435 / 500 |
| Random-150 | 88.2% | 23.31 ms | 5.13 | 0.3845 mJ | 0.0479 KB | 441 / 500 |

> Charts: `results/secure_rpl_metrics.png` · `results/baseline_vs_secure_comparison.png`

### Security Overhead vs Baseline

| Topology | PDR Drop | Delay Overhead |
|---|---|---|
| Star-50 | −1.2% | +8.1% |
| Mesh-100 | −2.0% | +10.7% |
| Tree-80 | −1.6% | +6.2% |
| Random-150 | −1.2% | +24.7% |

**Conclusion:** Security overhead is well within acceptable bounds — PDR drop < 2.5%, delay increase 6–25% (mainly from multi-hop crypto cost).

---

## Experiment 3 — Attack Simulations

### Replay Attack (`replay_attack.py`)

- **50 legitimate packets** sent; **20 replayed packets** injected.
- Sequence-number table correctly blocked **20/20 replays**.
- Detection accuracy: **100%** | False positive rate: **0%**
- Log: `outputs/replay_log.txt`

### Eavesdropping Attack (`eavesdropping_attack.py`)

- 5 sensitive sensor payloads (temperature, GPS, battery, alert, pressure) intercepted.
- Readable bytes recovered by attacker: **0 across all packets**.
- ChaCha20-Poly1305 ciphertext is computationally opaque without the key.
- Report: `outputs/eavesdropping_report.txt`

### Sinkhole Attack (`sinkhole_attack.py`)

- Malicious node **S3** falsely advertised `hop-count = 1` to attract traffic.
- Trust-score mechanism **detected S3 at round 2** (score dropped to 8.0 < threshold 50).
- Routing table automatically updated to avoid S3.
- Detection accuracy over **50 independent trials: 100%**
- Graph: `outputs/trust_scores.png` | Log: `outputs/sinkhole_log.txt`

### Node Capture Attack (`node_capture_atttack.py`)

| Phase | Result |
|---|---|
| Node N3 captured, key extracted | Attacker decrypted old traffic ✅ |
| Key revocation triggered | All 4 remaining nodes issued new keys |
| Post-revocation communication | Attacker **completely blocked** from cycle 1 |
| Secure comms restored at | **Routing cycle 1** |

- Log: `outputs/node_capture_recovery_log.txt`

> Chart: `results/attack_scenario_comparison.png`

---

## Security Design

### ChaCha20-Poly1305 (Hop-by-Hop)
Every forwarding node **decrypts** the incoming packet and **re-encrypts** it for the next hop using a 256-bit key and a random 96-bit nonce. The 16-byte Poly1305 tag provides both confidentiality and integrity.

### Replay Protection
Each node maintains a table `{sender_id → last_seq}`. Packets arriving with `seq ≤ last_seq` are silently discarded.

### Trust-Based Parent Selection
Parent score = `rank / (trust + ε)`. Nodes with higher trust get a lower effective score, making them preferred candidates. Trust degrades when a node misbehaves (e.g., drops packets, advertises false ranks).

### Key Revocation
When a node is identified as compromised, its key is immediately deleted from all neighbour tables. All remaining nodes are issued new keys via a re-keying broadcast. The compromised node can no longer participate in routing.

---

## Output Files

| File | Description |
|---|---|
| `results/topology_star_50.png` | Star topology diagram |
| `results/topology_mesh_100.png` | Mesh topology diagram |
| `results/topology_tree_80.png` | Tree topology diagram |
| `results/topology_random_150.png` | Random topology diagram |
| `results/dodag_star_50.png` | DODAG tree — Star |
| `results/dodag_mesh_100.png` | DODAG tree — Mesh |
| `results/dodag_tree_80.png` | DODAG tree — Tree |
| `results/dodag_random_150.png` | DODAG tree — Random |
| `results/traffic_summary_chart.png` | Baseline PDR / Delay / Hops bar chart |
| `results/secure_rpl_metrics.png` | Secure RPL 4-metric chart |
| `results/baseline_vs_secure_comparison.png` | Side-by-side comparison chart |
| `results/attack_scenario_comparison.png` | PDR/Delay under each attack |
| `results/baseline_traffic.csv` | 2000 packet records (baseline) |
| `results/secure_traffic.csv` | 2000 packet records (secure) |
| `results/full_summary.csv` | Aggregated topology comparison |
| `outputs/replay_log.txt` | Sequence-number replay detection log |
| `outputs/eavesdropping_report.txt` | Ciphertext interception analysis |
| `outputs/sinkhole_log.txt` | Trust-score sinkhole detection log |
| `outputs/trust_scores.png` | Per-node trust score graph |
| `outputs/node_capture_recovery_log.txt` | Key revocation & recovery log |

---

## License

MIT License — free to use for academic purposes.
