"""
traffic_generator.py — UDP Traffic Generator for RPL Network
Week 2 Assignment | RVU-CY-SI-26-10
Author: Priyanshi Sahu

Injects 500 UDP packets per topology and records:
  - PDR  (Packet Delivery Ratio %)
  - Delay (ms) — simulated propagation + queuing
  - Hop Count — hops from source to root
Saves results to results/baseline_traffic.csv
"""

import random
import csv
import os
import time
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np

from network import (IoTNode, build_star_topology, build_mesh_topology,
                     build_tree_topology, build_random_topology)
from rpl_baseline import RPLNetwork

# ── Simulation Parameters ─────────────────────────────────────────────────────
random.seed(42)

NUM_PACKETS        = 500
PROP_DELAY_PER_HOP = 2.5     # ms propagation delay per hop
QUEUE_DELAY_BASE   = 1.0     # ms base queuing delay
QUEUE_DELAY_JITTER = 0.5     # ms random jitter
DROP_PROB_BASE     = 0.02    # 2 % base packet drop probability per hop
ENERGY_DROP_THRESH = 50.0    # mJ — nodes below this may drop packets


# ══════════════════════════════════════════════════════════════════════════════
#  UDP Packet Simulator
# ══════════════════════════════════════════════════════════════════════════════

def simulate_udp_packet(src_id: int, rpl: RPLNetwork) -> dict:
    """
    Simulate one UDP packet from src_id to DODAG root.

    Returns a record dict with:
      packet_id, src_id, topology, delivered, delay_ms, hop_count, drop_reason
    """
    nodes         = rpl.nodes
    routing_table = rpl.routing_table

    entry = routing_table.get(src_id, {})
    if not entry.get('reachable', False):
        return {
            'delivered'  : False,
            'delay_ms'   : 0.0,
            'hop_count'  : 0,
            'drop_reason': 'UNREACHABLE'
        }

    hop_count   = entry['hop_count']
    if hop_count == 0:
        # Source IS the root
        return {
            'delivered'  : True,
            'delay_ms'   : 0.0,
            'hop_count'  : 0,
            'drop_reason': None
        }

    # Trace path from source to root
    path = []
    cur  = src_id
    visited = set()
    while cur is not None and cur not in visited:
        visited.add(cur)
        path.append(cur)
        cur = nodes[cur].preferred_parent

    total_delay   = 0.0
    drop_reason   = None

    for i, node_id in enumerate(path):
        node = nodes[node_id]

        # Energy check — low-energy nodes have higher drop chance
        energy_ratio  = node.energy / 1000.0
        drop_prob     = DROP_PROB_BASE + (1 - energy_ratio) * 0.05

        # Simulate transmit / receive energy cost
        if i < len(path) - 1:                   # not the root
            if not node.transmit_packet():
                drop_reason = 'NO_ENERGY'
                break

        # Probabilistic channel drop
        if random.random() < drop_prob:
            drop_reason = 'CHANNEL_DROP'
            node.packets_dropped += 1
            break

        # Accumulate delay
        total_delay += (PROP_DELAY_PER_HOP +
                        QUEUE_DELAY_BASE +
                        random.uniform(-QUEUE_DELAY_JITTER, QUEUE_DELAY_JITTER))

    delivered = drop_reason is None
    if delivered and path:
        nodes[path[-1]].receive_packet()   # root receives it

    return {
        'delivered'  : delivered,
        'delay_ms'   : round(total_delay, 3),
        'hop_count'  : len(path) - 1,
        'drop_reason': drop_reason
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Run traffic simulation for one topology
# ══════════════════════════════════════════════════════════════════════════════

def run_traffic(topology_name: str, nodes: list[IoTNode]) -> list[dict]:
    """
    Inject NUM_PACKETS UDP packets into the topology.
    Returns list of per-packet result records.
    """
    rpl = RPLNetwork(nodes)
    rpl.run()

    # Only use reachable, non-root nodes as sources
    sources = [
        nid for nid, entry in rpl.routing_table.items()
        if entry['reachable'] and not rpl.nodes[nid].is_root
    ]

    records = []
    for pkt_id in range(1, NUM_PACKETS + 1):
        src_id = random.choice(sources)
        result = simulate_udp_packet(src_id, rpl)
        records.append({
            'packet_id'   : pkt_id,
            'topology'    : topology_name,
            'src_node'    : src_id,
            'delivered'   : result['delivered'],
            'delay_ms'    : result['delay_ms'],
            'hop_count'   : result['hop_count'],
            'drop_reason' : result['drop_reason'] or 'NONE'
        })

    return records


# ══════════════════════════════════════════════════════════════════════════════
#  Summary statistics
# ══════════════════════════════════════════════════════════════════════════════

def summarise(records: list[dict]) -> dict:
    delivered   = [r for r in records if r['delivered']]
    pdr         = len(delivered) / len(records) * 100
    avg_delay   = (sum(r['delay_ms']   for r in delivered) / len(delivered)) if delivered else 0
    avg_hops    = (sum(r['hop_count']  for r in delivered) / len(delivered)) if delivered else 0
    return {
        'total'    : len(records),
        'delivered': len(delivered),
        'pdr'      : round(pdr, 2),
        'avg_delay': round(avg_delay, 3),
        'avg_hops' : round(avg_hops, 2)
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Save to CSV
# ══════════════════════════════════════════════════════════════════════════════

def save_csv(all_records: list[dict], path: str):
    fieldnames = ['packet_id', 'topology', 'src_node',
                  'delivered', 'delay_ms', 'hop_count', 'drop_reason']
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_records)
    print(f"  ✓ CSV saved: {path}  ({len(all_records)} rows)")


# ══════════════════════════════════════════════════════════════════════════════
#  Result Visualisation
# ══════════════════════════════════════════════════════════════════════════════

def save_results_chart(summaries: dict, path: str):
    topos  = list(summaries.keys())
    pdrs   = [summaries[t]['pdr']       for t in topos]
    delays = [summaries[t]['avg_delay'] for t in topos]
    hops   = [summaries[t]['avg_hops']  for t in topos]

    fig = plt.figure(figsize=(14, 5), facecolor='#0F1923')
    gs  = gridspec.GridSpec(1, 3, figure=fig, wspace=0.4)

    colors = ['#FF6B35', '#00D4FF', '#7FFF00', '#FF00FF']

    for ax_idx, (vals, label, unit) in enumerate([
        (pdrs,   'PDR (%)',          '%'),
        (delays, 'Avg Delay (ms)',   'ms'),
        (hops,   'Avg Hop Count',    'hops'),
    ]):
        ax = fig.add_subplot(gs[ax_idx])
        ax.set_facecolor('#1A2B3C')
        bars = ax.bar(topos, vals, color=colors, edgecolor='#0F1923', width=0.55)
        ax.set_title(label, color='white', fontsize=12, fontweight='bold', pad=8)
        ax.tick_params(colors='white', labelsize=8)
        ax.spines[:].set_color('#2A4A6B')
        for bar, val in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + max(vals)*0.02,
                    f"{val:.1f}{unit}", ha='center', va='bottom',
                    color='white', fontsize=8, fontweight='bold')
        ax.set_ylim(0, max(vals) * 1.18)
        plt.setp(ax.get_xticklabels(), rotation=15, ha='right')

    fig.suptitle("Baseline Traffic Results — 500 UDP Packets × 4 Topologies",
                 color='white', fontsize=13, fontweight='bold', y=1.02)
    plt.savefig(path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✓ Chart saved: {path}")


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    os.makedirs("results", exist_ok=True)

    configs = [
        ("Star-50",    build_star_topology,    50),
        ("Mesh-100",   build_mesh_topology,   100),
        ("Tree-80",    build_tree_topology,    80),
        ("Random-150", build_random_topology, 150),
    ]

    all_records = []
    summaries   = {}

    print(f"\n{'='*58}")
    print(f"  TRAFFIC GENERATOR — {NUM_PACKETS} UDP packets per topology")
    print(f"{'='*58}")

    for name, builder, n in configs:
        print(f"\n  ► {name}")
        nodes, _ = builder(n)
        records  = run_traffic(name, nodes)
        all_records.extend(records)

        s = summarise(records)
        summaries[name] = s
        print(f"    PDR       : {s['pdr']}%")
        print(f"    Avg Delay : {s['avg_delay']} ms")
        print(f"    Avg Hops  : {s['avg_hops']}")
        print(f"    Delivered : {s['delivered']} / {s['total']}")

    # Save CSV
    print()
    save_csv(all_records, "results/baseline_traffic.csv")

    # Save summary chart
    save_results_chart(summaries, "results/traffic_summary_chart.png")

    # Print summary table
    print(f"\n{'─'*58}")
    print(f"  {'Topology':<14} {'PDR%':>7} {'Delay(ms)':>11} {'Hops':>6}")
    print(f"{'─'*58}")
    for name, s in summaries.items():
        print(f"  {name:<14} {s['pdr']:>7.2f} {s['avg_delay']:>11.3f} {s['avg_hops']:>6.2f}")
    print(f"{'─'*58}")
    print(f"\n  traffic_generator.py complete!\n")


if __name__ == "__main__":
    main()