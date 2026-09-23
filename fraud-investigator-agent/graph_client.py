import logging
from typing import Dict, Any, List
import networkx as nx

logger = logging.getLogger("fraud_agent.graph")

class TigerGraphFraudClient:
    def __init__(self, host: str, graphname: str, username: str, password: str):
        self.host = host
        self.graphname = graphname
        self._connected = False
        self.conn = None
        
        # In-memory graph fallback
        self.mock_graph = nx.DiGraph()
        self._init_mock_subgraph()
        self._try_connect(username, password)

    def _try_connect(self, username: str, password: str):
        try:
            import pyTigerGraph as tg
            self.conn = tg.TigerGraphConnection(
                host=self.host,
                graphname=self.graphname,
                username=username,
                password=password
            )
            logger.info("TigerGraph cluster connection configured.")
        except Exception as e:
            logger.warning(f"Could not connect to live TigerGraph cluster: {e}. Defaulting to internal Graph Engine.")
            self._connected = False

    def _init_mock_subgraph(self):
        """Populate a realistic subgraph with mule networks and device clusters."""
        # Nodes
        self.mock_graph.add_node("usr_victim_101", type="User", risk_score=0.2, flagged=False)
        self.mock_graph.add_node("usr_mule_303", type="User", risk_score=0.88, flagged=True)
        self.mock_graph.add_node("usr_syndicate_404", type="User", risk_score=0.92, flagged=True)

        self.mock_graph.add_node("acc_101", type="Account", balance=1400.0)
        self.mock_graph.add_node("acc_303", type="Account", balance=28000.0)
        self.mock_graph.add_node("acc_404", type="Account", balance=500.0)

        self.mock_graph.add_node("dev_iphone_xyz", type="Device", fingerprint="fp_ios_998")
        self.mock_graph.add_node("ip_vpn_exit", type="IPAddress", proxy=True, country="NL")

        # Edges
        self.mock_graph.add_edge("usr_victim_101", "acc_101", rel="OWNS")
        self.mock_graph.add_edge("usr_mule_303", "acc_303", rel="OWNS")
        self.mock_graph.add_edge("usr_syndicate_404", "acc_404", rel="OWNS")

        # Infrastructure sharing (Mule and Syndicate share the exact same device and proxy)
        self.mock_graph.add_edge("usr_mule_303", "dev_iphone_xyz", rel="USED_DEVICE")
        self.mock_graph.add_edge("usr_syndicate_404", "dev_iphone_xyz", rel="USED_DEVICE")
        self.mock_graph.add_edge("usr_mule_303", "ip_vpn_exit", rel="ACCESSED_FROM")
        self.mock_graph.add_edge("usr_syndicate_404", "ip_vpn_exit", rel="ACCESSED_FROM")

        # Rapid money hop: Victim -> Mule -> Syndicate
        self.mock_graph.add_edge("acc_101", "acc_303", rel="TRANSFERRED", amount=9800.0, timestamp=1710001000)
        self.mock_graph.add_edge("acc_303", "acc_404", rel="TRANSFERRED", amount=9600.0, timestamp=1710001400)

    def trace_money_chain(self, start_account: str, max_depth: int = 3) -> List[Dict[str, Any]]:
        """Finds multi-hop rapid disbursements (Layering / Mule behavior)."""
        chain = []
        curr = start_account
        for _ in range(max_depth):
            out_edges = [(u, v, d) for u, v, d in self.mock_graph.out_edges(curr, data=True) if d.get("rel") == "TRANSFERRED"]
            if not out_edges:
                break
            u, v, data = out_edges[0]
            chain.append({"from": u, "to": v, "amount": data.get("amount", 0.0), "ts": data.get("timestamp")})
            curr = v
        return chain

    def get_shared_infrastructure(self, user_id: str) -> Dict[str, Any]:
        """Graph traversal to inspect shared devices, IPs, and connected syndicates."""
        if user_id not in self.mock_graph:
            return {"shared_devices": [], "shared_ips": [], "cluster_users": []}

        infra_nodes = [v for _, v in self.mock_graph.out_edges(user_id)]
        connected_users = set()

        for node in infra_nodes:
            for u, _ in self.mock_graph.in_edges(node):
                if u != user_id and self.mock_graph.nodes[u].get("type") == "User":
                    connected_users.add(u)

        return {
            "shared_infrastructure": infra_nodes,
            "connected_peer_users": list(connected_users),
            "known_bad_actors_in_cluster": [u for u in connected_users if self.mock_graph.nodes[u].get("flagged")]
        }