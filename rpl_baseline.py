# rpl_baseline.py
"""Baseline RPL (Routing Protocol for Low‑Power and Lossy Networks) implementation.
This module provides a minimal RPL node class with basic packet forwarding based on rank.
It is intentionally simple and serves as a foundation for the SecureRPLNode defined in
`secure_rpl.py`.
"""

from typing import Dict, List, Optional
import random

class Packet:
    """Simple packet structure for baseline RPL.
    Attributes:
        src (int): Source node ID.
        dst (int): Destination node ID.
        payload (bytes): Payload data.
        seq (int): Sequence number (optional, used by SecureRPLNode).
    """
    def __init__(self, src: int, dst: int, payload: bytes, seq: int = 0):
        self.src = src
        self.dst = dst
        self.payload = payload
        self.seq = seq

class RPLNode:
    """Baseline RPL node.
    Args:
        node_id (int): Unique identifier for the node.
        rank (float): Node rank (lower is better). In a real network this is derived from
            metrics such as ETX. Here we use a random rank for demonstration.
    """
    def __init__(self, node_id: int, rank: Optional[float] = None):
        self.node_id = node_id
        self.rank = rank if rank is not None else random.uniform(1, 10)
        self.neighbors: List["RPLNode"] = []
        self.parent: Optional["RPLNode"] = None
        self.received_seq: Dict[int, int] = {}

    def add_neighbor(self, neighbor: "RPLNode") -> None:
        if neighbor not in self.neighbors:
            self.neighbors.append(neighbor)
            neighbor.neighbors.append(self)

    def select_parent(self) -> None:
        """Select parent based solely on the lowest rank among neighbors."""
        if not self.neighbors:
            self.parent = None
            return
        self.parent = min(self.neighbors, key=lambda n: n.rank)

    def forward_packet(self, packet: Packet) -> None:
        """Forward a packet towards its destination.
        This baseline implementation simply forwards to the parent if one exists,
        otherwise drops the packet.
        """
        if self.parent is None:
            self.select_parent()
        if self.parent:
            self.parent.receive_packet(packet)

    def receive_packet(self, packet: Packet) -> None:
        """Handle an incoming packet.
        If the packet is destined for this node, the payload is processed; otherwise the
        node forwards it.
        """
        if packet.dst == self.node_id:
            self._process_payload(packet.payload)
        else:
            self.forward_packet(packet)

    def _process_payload(self, payload: bytes) -> None:
        # Placeholder for payload handling logic.
        pass

    def __repr__(self) -> str:
        return f"RPLNode(id={self.node_id}, rank={self.rank:.2f})"
