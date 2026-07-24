import random
import math
import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import os

random.seed(42)

TX_ENERGY_COST   = 0.05   # mJ per packet transmitted
RX_ENERGY_COST   = 0.02   # mJ per packet received
COMM_RANGE       = 50.0   # metres — nodes within this range are neighbours
INITIAL_ENERGY   = 1000.0 # mJ
INITIAL_MEMORY   = 256.0 # KB
class IoTNode:
    """
    Represents a single IoT sensor node with energy, memory,
    position, packet counters, and a neighbour table.
    """

    def __init__(self, node_id: int, x: float, y: float,
                 energy: float = INITIAL_ENERGY,
                 memory: float = INITIAL_MEMORY):
        self.node_id   = node_id
        self.x         = x
        self.y         = y
        self.energy    = energy          # mJ remaining
        self.memory    = memory          # KB available

        # Packet counters
        self.packets_sent     = 0
        self.packets_received = 0
        self.packets_dropped  = 0

        # Neighbour table: {neighbour_id: distance_metres}
        self.neighbour_table: dict[int, float] = {}

        # RPL fields (used by rpl_baseline.py)
        self.rank          = float('inf')  # RPL rank (lower = closer to root)
        self.preferred_parent = None       # node_id of preferred parent
        self.is_root       = False

    # ── Energy helpers ────────────────────────────────────────────────────────
    def transmit_packet(self) -> bool:
        """Attempt to transmit one packet. Returns False if out of energy."""
        if self.energy < TX_ENERGY_COST:
            self.packets_dropped += 1
            return False
        self.energy -= TX_ENERGY_COST
        self.packets_sent += 1
        return True

    def receive_packet(self) -> bool:
        """Attempt to receive one packet. Returns False if out of energy."""
        if self.energy < RX_ENERGY_COST:
            self.packets_dropped += 1
            return False
        self.energy -= RX_ENERGY_COST
        self.packets_received += 1
        return True

    # ── Neighbour table helpers ───────────────────────────────────────────────
    def add_neighbour(self, other: 'IoTNode'):
        dist = math.dist((self.x, self.y), (other.x, other.y))
        self.neighbour_table[other.node_id] = round(dist, 2)

    def distance_to(self, other: 'IoTNode') -> float:
        return math.dist((self.x, self.y), (other.x, other.y))

    # ── Representation ────────────────────────────────────────────────────────
    def __repr__(self):
        return (f"IoTNode(id={self.node_id}, pos=({self.x:.1f},{self.y:.1f}), "
                f"energy={self.energy:.1f}mJ, neighbours={list(self.neighbour_table.keys())})")


# ══════════════════════════════════════════════════════════════════════════════
#  Topology Builders
# ══════════════════════════════════════════════════════════════════════════════

def _build_neighbour_tables(nodes: list[IoTNode], comm_range: float = COMM_RANGE):
    """Link nodes that are within comm_range of each other."""
    for i, n1 in enumerate(nodes):
        for j, n2 in enumerate(nodes):
            if i != j and n1.distance_to(n2) <= comm_range:
                n1.add_neighbour(n2)


def build_star_topology(n: int = 50) -> tuple[list[IoTNode], nx.Graph]:
    """
    Star topology: one central hub (node 0) connected to all others.
    Hub is placed at centre; leaf nodes arranged in a circle.
    """
    nodes = []
    cx, cy = 200.0, 200.0
    hub = IoTNode(0, cx, cy)
    hub.is_root = True
    nodes.append(hub)

    radius = 150.0
    for i in range(1, n):
        angle = 2 * math.pi * i / (n - 1)
        x = cx + radius * math.cos(angle)
        y = cy + radius * math.sin(angle)
        nodes.append(IoTNode(i, x, y))

    # In star topology every leaf connects only to hub
    for node in nodes[1:]:
        node.add_neighbour(hub)
        hub.add_neighbour(node)

    G = nx.star_graph(n - 1)
    return nodes, G


def build_mesh_topology(n: int = 100) -> tuple[list[IoTNode], nx.Graph]:
    """
    Mesh topology: nodes placed in a grid, connected to all
    neighbours within COMM_RANGE.
    """
    nodes = []
    cols  = math.ceil(math.sqrt(n))
    spacing = 40.0
    for i in range(n):
        x = (i % cols) * spacing
        y = (i // cols) * spacing
        node = IoTNode(i, x, y)
        if i == 0:
            node.is_root = True
        nodes.append(node)

    _build_neighbour_tables(nodes, comm_range=COMM_RANGE)

    G = nx.Graph()
    G.add_nodes_from(range(n))
    for node in nodes:
        for nb_id in node.neighbour_table:
            G.add_edge(node.node_id, nb_id)
    return nodes, G


def build_tree_topology(n: int = 80) -> tuple[list[IoTNode], nx.Graph]:
    """
    Tree topology: balanced binary tree.
    Node 0 is root; children at 2i+1, 2i+2.
    """
    nodes = []
    # Assign positions using level + horizontal offset
    for i in range(n):
        level = math.floor(math.log2(i + 1)) if i > 0 else 0
        pos_in_level = i - (2 ** level - 1)
        total_in_level = 2 ** level
        x = (pos_in_level + 0.5) * (400.0 / total_in_level)
        y = 350.0 - level * 40.0
        node = IoTNode(i, x, y)
        if i == 0:
            node.is_root = True
        nodes.append(node)

    h = int(math.log2(n))
    G_full = nx.balanced_tree(r=2, h=h)
    # Keep only nodes that exist in our list
    actual_n = len(nodes)
    G = nx.Graph()
    G.add_nodes_from(range(actual_n))
    for u, v in G_full.edges():
        if u < actual_n and v < actual_n:
            G.add_edge(u, v)
            nodes[u].add_neighbour(nodes[v])
            nodes[v].add_neighbour(nodes[u])
    return nodes, G


def build_random_topology(n: int = 150) -> tuple[list[IoTNode], nx.Graph]:
    """
    Random topology: nodes scattered randomly in a 400×400 grid,
    connected if within COMM_RANGE.
    """
    nodes = []
    for i in range(n):
        x = random.uniform(0, 400)
        y = random.uniform(0, 400)
        node = IoTNode(i, x, y)
        if i == 0:
            node.is_root = True
        nodes.append(node)

    _build_neighbour_tables(nodes, comm_range=COMM_RANGE)

    G = nx.Graph()
    G.add_nodes_from(range(n))
    for node in nodes:
        for nb_id in node.neighbour_table:
            G.add_edge(node.node_id, nb_id)
    return nodes, G


# ══════════════════════════════════════════════════════════════════════════════
#  Visualisation
# ══════════════════════════════════════════════════════════════════════════════

def _save_topology_png(nodes: list[IoTNode], G: nx.Graph,
                       title: str, filename: str, layout: str = "spring"):
    fig, ax = plt.subplots(figsize=(10, 8))
    fig.patch.set_facecolor('#0F1923')
    ax.set_facecolor('#0F1923')

    # Node positions
    pos = {n.node_id: (n.x, n.y) for n in nodes}

    node_ids  = [n.node_id for n in nodes]
    colors    = ['#FF6B35' if n.is_root else '#00D4FF' for n in nodes]
    sizes     = [300 if n.is_root else 60 for n in nodes]

    nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#2A4A6B',
                           width=0.6, alpha=0.6,
                           nodelist=[nd for nd in G.nodes() if nd < len(nodes)])
    nx.draw_networkx_nodes(G, pos, ax=ax, nodelist=node_ids,
                           node_color=colors, node_size=sizes, alpha=0.95)

    # Label only root
    root_label = {n.node_id: f"ROOT\n({n.node_id})" for n in nodes if n.is_root}
    nx.draw_networkx_labels(G, pos, labels=root_label, ax=ax,
                            font_color='white', font_size=7, font_weight='bold')

    # Legend
    root_patch = mpatches.Patch(color='#FF6B35', label='Root / Sink Node')
    node_patch = mpatches.Patch(color='#00D4FF', label='Sensor Node')
    ax.legend(handles=[root_patch, node_patch], loc='lower right',
              facecolor='#1A2B3C', labelcolor='white', fontsize=9)

    ax.set_title(title, color='white', fontsize=14, fontweight='bold', pad=15)
    ax.axis('off')
    plt.tight_layout()
    plt.savefig(filename, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"  ✓ Saved: {filename}")


# ══════════════════════════════════════════════════════════════════════════════
#  Smoke Tests
# ══════════════════════════════════════════════════════════════════════════════

def smoke_tests():
    print("\n" + "="*55)
    print("  SMOKE TESTS — network.py")
    print("="*55)
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            print(f"  ✅ PASS  {name}")
            passed += 1
        else:
            print(f"  ❌ FAIL  {name}")
            failed += 1

    # Test IoTNode creation
    n = IoTNode(1, 10.0, 20.0)
    check("Node creation with correct id",    n.node_id == 1)
    check("Node initial energy = 1000 mJ",   n.energy == 1000.0)
    check("Node initial memory = 256 KB",    n.memory == 256.0)
    check("Node position (x,y)",             n.x == 10.0 and n.y == 20.0)
    check("Packet counters initialised to 0",
          n.packets_sent == 0 and n.packets_received == 0 and n.packets_dropped == 0)

    # Test energy deduction
    n.transmit_packet()
    check("Transmit deducts TX energy",      abs(n.energy - (1000.0 - TX_ENERGY_COST)) < 1e-9)
    check("packets_sent increments",         n.packets_sent == 1)

    n.receive_packet()
    check("Receive deducts RX energy",
          abs(n.energy - (1000.0 - TX_ENERGY_COST - RX_ENERGY_COST)) < 1e-9)
    check("packets_received increments",     n.packets_received == 1)

    # Test neighbour table
    n2 = IoTNode(2, 15.0, 20.0)
    n.add_neighbour(n2)
    check("Neighbour added correctly",       2 in n.neighbour_table)
    check("Distance computed correctly",     abs(n.neighbour_table[2] - 5.0) < 0.01)

    # Test topologies
    nodes_s, G_s = build_star_topology(50)
    check("Star: 50 nodes created",          len(nodes_s) == 50)
    check("Star: hub has 49 neighbours",     len(nodes_s[0].neighbour_table) == 49)
    check("Star: root flag set on hub",      nodes_s[0].is_root)

    nodes_m, G_m = build_mesh_topology(100)
    check("Mesh: 100 nodes created",         len(nodes_m) == 100)
    check("Mesh: graph has edges",           G_m.number_of_edges() > 0)

    nodes_t, G_t = build_tree_topology(80)
    check("Tree: ≥ 63 nodes created",        len(nodes_t) >= 63)
    check("Tree: root is node 0",            nodes_t[0].is_root)

    nodes_r, G_r = build_random_topology(150)
    check("Random: 150 nodes created",       len(nodes_r) == 150)
    check("Random: graph has edges",         G_r.number_of_edges() > 0)

    print(f"\n  Results: {passed} passed, {failed} failed")
    print("="*55)
    return passed, failed


# ══════════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    os.makedirs("results", exist_ok=True)

    print("\n Building topologies and saving PNG diagrams...")

    nodes_s, G_s = build_star_topology(50)
    _save_topology_png(nodes_s, G_s,
        "Star Topology — 50 Nodes", "results/topology_star_50.png")

    nodes_m, G_m = build_mesh_topology(100)
    _save_topology_png(nodes_m, G_m,
        "Mesh Topology — 100 Nodes", "results/topology_mesh_100.png")

    nodes_t, G_t = build_tree_topology(80)
    _save_topology_png(nodes_t, G_t,
        "Tree Topology — 80 Nodes", "results/topology_tree_80.png")

    nodes_r, G_r = build_random_topology(150)
    _save_topology_png(nodes_r, G_r,
        "Random Topology — 150 Nodes", "results/topology_random_150.png")

    passed, failed = smoke_tests()

    print(f"\n{'='*55}")
    print(f"  network.py complete. Topology PNGs saved to results/")
    print(f"{'='*55}\n")

    return nodes_s, nodes_m, nodes_t, nodes_r


if __name__ == "__main__":
    main()