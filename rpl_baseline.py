"""
rpl_baseline.py — Baseline RPL Routing Implementation
Week 2 Assignment | RVU-CY-SI-26-10
Author: Priyanshi Sahu

Implements:
  - DODAG construction with OF0 (hop-count objective function)
  - DIO / DIS / DAO control messages
  - Trickle timer
  - Parent selection
  - Routing table output + DODAG visualisation (PNG)
"""

import math
import time
import collections
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
import os

from network import (IoTNode, build_star_topology, build_mesh_topology,
                     build_tree_topology, build_random_topology)

# ── RPL Constants ─────────────────────────────────────────────────────────────
ROOT_RANK        = 1        # Rank of the DODAG root
INFINITE_RANK    = 0xFFFF   # Unreachable rank
RANK_INCREMENT   = 1        # OF0: each hop adds 1 to rank
MIN_HOP_RANK_INC = 1

# Trickle timer parameters (in simulation ticks)
IMIN   = 2    # minimum interval
IMAX   = 8    # maximum doublings
K      = 1    # redundancy constant


# ══════════════════════════════════════════════════════════════════════════════
#  Control Message Dataclasses (plain dicts for simplicity)
# ══════════════════════════════════════════════════════════════════════════════

def make_DIO(sender_id: int, rank: int, dodag_id: int = 0) -> dict:
    """DODAG Information Object — advertises rank and DODAG membership."""
    return {
        'type'     : 'DIO',
        'sender_id': sender_id,
        'rank'     : rank,
        'dodag_id' : dodag_id,
        'timestamp': time.time()
    }

def make_DIS(sender_id: int) -> dict:
    """DODAG Information Solicitation — new node requests DODAG info."""
    return {
        'type'     : 'DIS',
        'sender_id': sender_id,
        'timestamp': time.time()
    }

def make_DAO(sender_id: int, parent_id: int, rank: int) -> dict:
    """Destination Advertisement Object — registers route with parent/root."""
    return {
        'type'     : 'DAO',
        'sender_id': sender_id,
        'parent_id': parent_id,
        'rank'     : rank,
        'timestamp': time.time()
    }


# ══════════════════════════════════════════════════════════════════════════════
#  Trickle Timer
# ══════════════════════════════════════════════════════════════════════════════

class TrickleTimer:
    """
    Trickle algorithm: sends DIO messages less often when network is stable.
    Interval doubles each round (up to IMAX doublings), resets on inconsistency.
    """

    def __init__(self):
        self.I     = IMIN      # current interval
        self.t     = IMIN // 2 # fire time within interval
        self.c     = 0         # consistency counter
        self.ticks = 0         # simulation ticks elapsed

    def tick(self) -> bool:
        """Advance timer by 1 tick. Returns True when DIO should be sent."""
        self.ticks += 1
        if self.ticks >= self.t:
            # Fire if redundancy threshold not met
            if self.c < K:
                self._double_interval()
                return True
            self._double_interval()
        return False

    def hear_consistent(self):
        """Called when a consistent DIO is received — increment counter."""
        self.c += 1

    def reset(self):
        """Called on inconsistency — restart from IMIN."""
        self.I     = IMIN
        self.t     = IMIN // 2
        self.c     = 0
        self.ticks = 0

    def _double_interval(self):
        doublings = round(math.log2(self.I / IMIN)) if self.I > IMIN else 0
        if doublings < IMAX:
            self.I = min(self.I * 2, IMIN * (2 ** IMAX))
        self.t     = self.I // 2 + (self.I // 2)
        self.c     = 0
        self.ticks = 0


# ══════════════════════════════════════════════════════════════════════════════
#  RPL DODAG Builder
# ══════════════════════════════════════════════════════════════════════════════

class RPLNetwork:
    """
    Simulates RPL DODAG construction on a list of IoTNode objects.

    Phase 1 — DIS:   New nodes broadcast DIS to discover the DODAG.
    Phase 2 — DIO:   Root sends DIO; nodes propagate it hop by hop.
    Phase 3 — DAO:   Each node sends DAO to its preferred parent.
    Phase 4 — Table: Routing table is assembled at root.
    """

    def __init__(self, nodes: list[IoTNode]):
        self.nodes     = {n.node_id: n for n in nodes}
        self.root      = next(n for n in nodes if n.is_root)
        self.dio_log   : list[dict] = []
        self.dis_log   : list[dict] = []
        self.dao_log   : list[dict] = []
        self.routing_table: dict[int, dict] = {}   # node_id → {parent, rank, next_hop}
        self.trickle   = TrickleTimer()

        # Reset all ranks
        for n in nodes:
            n.rank = INFINITE_RANK
            n.preferred_parent = None
        self.root.rank = ROOT_RANK

    # ── Phase 1: DIS ──────────────────────────────────────────────────────────
    def _run_dis_phase(self):
        """Every non-root node broadcasts a DIS to solicit DIO from neighbours."""
        for node in self.nodes.values():
            if not node.is_root:
                msg = make_DIS(node.node_id)
                self.dis_log.append(msg)
                node.transmit_packet()

    # ── Phase 2: DIO (BFS from root) ─────────────────────────────────────────
    def _run_dio_phase(self):
        """
        Root broadcasts DIO with rank=1.
        Each node that hears it sets rank = parent_rank + RANK_INCREMENT
        and re-broadcasts. BFS ensures correct ordering.
        """
        queue    = collections.deque([self.root.node_id])
        visited  = {self.root.node_id}

        while queue:
            current_id = queue.popleft()
            current    = self.nodes[current_id]

            # Send DIO from current node
            dio = make_DIO(current_id, current.rank)
            self.dio_log.append(dio)
            current.transmit_packet()

            # Trickle: check if we should send
            self.trickle.tick()

            # Neighbours receive DIO and update rank if beneficial
            for nb_id in current.neighbour_table:
                if nb_id not in self.nodes:
                    continue
                nb = self.nodes[nb_id]
                candidate_rank = current.rank + RANK_INCREMENT

                # OF0: accept if improves rank (lower = better)
                if candidate_rank < nb.rank:
                    nb.rank             = candidate_rank
                    nb.preferred_parent = current_id
                    nb.receive_packet()
                    self.trickle.hear_consistent()

                    if nb_id not in visited:
                        visited.add(nb_id)
                        queue.append(nb_id)

    # ── Phase 3: DAO ──────────────────────────────────────────────────────────
    def _run_dao_phase(self):
        """
        Each node sends DAO upward to its preferred parent,
        registering a downward route to itself.
        """
        for node in self.nodes.values():
            if node.is_root or node.preferred_parent is None:
                continue
            dao = make_DAO(node.node_id, node.preferred_parent, node.rank)
            self.dao_log.append(dao)
            node.transmit_packet()

            # Parent receives the DAO
            parent = self.nodes.get(node.preferred_parent)
            if parent:
                parent.receive_packet()

    # ── Phase 4: Build routing table ──────────────────────────────────────────
    def _build_routing_table(self):
        """
        Assemble the routing table.
        Each entry: node_id → {parent_id, rank, next_hop_to_root, hop_count}
        """
        for node in self.nodes.values():
            if node.is_root:
                self.routing_table[node.node_id] = {
                    'parent_id'      : None,
                    'rank'           : ROOT_RANK,
                    'next_hop_to_root': node.node_id,
                    'hop_count'      : 0,
                    'reachable'      : True
                }
                continue

            if node.preferred_parent is None:
                self.routing_table[node.node_id] = {
                    'parent_id'      : None,
                    'rank'           : INFINITE_RANK,
                    'next_hop_to_root': None,
                    'hop_count'      : -1,
                    'reachable'      : False
                }
                continue

            # Trace path to root to find next_hop and hop_count
            path       = []
            current_id = node.node_id
            visited    = set()
            while current_id is not None and current_id not in visited:
                visited.add(current_id)
                path.append(current_id)
                current_id = self.nodes[current_id].preferred_parent

            next_hop   = path[1] if len(path) > 1 else node.node_id
            hop_count  = len(path) - 1  # edges to root

            self.routing_table[node.node_id] = {
                'parent_id'       : node.preferred_parent,
                'rank'            : node.rank,
                'next_hop_to_root': next_hop,
                'hop_count'       : hop_count,
                'reachable'       : True
            }

    # ── Public: run full RPL ──────────────────────────────────────────────────
    def run(self):
        """Execute all 4 RPL phases."""
        self._run_dis_phase()
        self._run_dio_phase()
        self._run_dao_phase()
        self._build_routing_table()

    # ── Print routing table ───────────────────────────────────────────────────
    def print_routing_table(self, max_rows: int = 20):
        print(f"\n{'─'*70}")
        print(f"  ROUTING TABLE  (showing first {max_rows} entries)")
        print(f"{'─'*70}")
        print(f"  {'Node':>5}  {'Parent':>7}  {'Rank':>6}  "
              f"{'Next Hop':>9}  {'Hops':>5}  {'Status':>10}")
        print(f"{'─'*70}")
        for nid, entry in list(self.routing_table.items())[:max_rows]:
            status = "REACHABLE" if entry['reachable'] else "ISOLATED"
            print(f"  {nid:>5}  {str(entry['parent_id']):>7}  "
                  f"{entry['rank']:>6}  {str(entry['next_hop_to_root']):>9}  "
                  f"{entry['hop_count']:>5}  {status:>10}")
        reachable = sum(1 for e in self.routing_table.values() if e['reachable'])
        print(f"{'─'*70}")
        print(f"  Total: {len(self.nodes)} nodes | "
              f"Reachable: {reachable} | "
              f"Isolated: {len(self.nodes)-reachable}")
        print(f"  DIS sent: {len(self.dis_log)} | "
              f"DIO sent: {len(self.dio_log)} | "
              f"DAO sent: {len(self.dao_log)}")
        print(f"{'─'*70}")

    # ── DODAG Visualisation ───────────────────────────────────────────────────
    def save_dodag_png(self, filename: str, title: str = "DODAG Tree"):
        """Draw the DODAG tree using preferred-parent edges."""
        G   = nx.DiGraph()
        pos = {}
        for nid, node in self.nodes.items():
            G.add_node(nid)
            pos[nid] = (node.x, node.y)

        for nid, entry in self.routing_table.items():
            if entry['parent_id'] is not None:
                G.add_edge(nid, entry['parent_id'])  # child → parent

        fig, ax = plt.subplots(figsize=(11, 9))
        fig.patch.set_facecolor('#0F1923')
        ax.set_facecolor('#0F1923')

        node_colors = []
        node_sizes  = []
        for nid in G.nodes():
            node  = self.nodes[nid]
            entry = self.routing_table.get(nid, {})
            if node.is_root:
                node_colors.append('#FF6B35')
                node_sizes.append(400)
            elif not entry.get('reachable', False):
                node_colors.append('#888888')
                node_sizes.append(40)
            else:
                # colour by hop count (blue gradient)
                hops = entry.get('hop_count', 1)
                intensity = max(0.2, 1.0 - hops * 0.12)
                node_colors.append(plt.cm.cool(intensity))
                node_sizes.append(80)

        nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#3A7CA5',
                               arrows=True, arrowsize=8,
                               width=0.8, alpha=0.7,
                               connectionstyle='arc3,rad=0.05')
        nx.draw_networkx_nodes(G, pos, ax=ax,
                               node_color=node_colors, node_size=node_sizes,
                               alpha=0.92)

        root_lbl = {nid: f"ROOT" for nid, n in self.nodes.items() if n.is_root}
        nx.draw_networkx_labels(G, pos, labels=root_lbl, ax=ax,
                                font_color='white', font_size=7, font_weight='bold')

        root_p   = mpatches.Patch(color='#FF6B35', label='Root (Rank 1)')
        reach_p  = mpatches.Patch(color='#00D4FF', label='Reachable Node')
        isol_p   = mpatches.Patch(color='#888888', label='Isolated Node')
        ax.legend(handles=[root_p, reach_p, isol_p], loc='lower right',
                  facecolor='#1A2B3C', labelcolor='white', fontsize=9)

        reachable = sum(1 for e in self.routing_table.values() if e['reachable'])
        ax.set_title(
            f"{title}\n"
            f"Nodes: {len(self.nodes)}  |  "
            f"Reachable: {reachable}  |  "
            f"DIO: {len(self.dio_log)}  DAO: {len(self.dao_log)}",
            color='white', fontsize=12, fontweight='bold', pad=12
        )
        ax.axis('off')
        plt.tight_layout()
        plt.savefig(filename, dpi=150, bbox_inches='tight',
                    facecolor=fig.get_facecolor())
        plt.close()
        print(f"  ✓ DODAG saved: {filename}")


# ══════════════════════════════════════════════════════════════════════════════
#  Main — run on all 4 topologies
# ══════════════════════════════════════════════════════════════════════════════

def main():
    os.makedirs("results", exist_ok=True)

    configs = [
        ("Star-50",    build_star_topology,   50,  "results/dodag_star_50.png"),
        ("Mesh-100",   build_mesh_topology,  100,  "results/dodag_mesh_100.png"),
        ("Tree-80",    build_tree_topology,   80,  "results/dodag_tree_80.png"),
        ("Random-150", build_random_topology,150,  "results/dodag_random_150.png"),
    ]

    all_networks = {}

    for name, builder, n, png_path in configs:
        print(f"\n{'='*55}")
        print(f"  Running RPL on {name} topology")
        print(f"{'='*55}")
        nodes, _ = builder(n)
        rpl      = RPLNetwork(nodes)
        rpl.run()
        rpl.print_routing_table(max_rows=15)
        rpl.save_dodag_png(png_path, title=f"DODAG — {name}")
        all_networks[name] = rpl

    print(f"\n{'='*55}")
    print("  rpl_baseline.py complete!")
    print(f"{'='*55}\n")
    return all_networks


if __name__ == "__main__":
    main()