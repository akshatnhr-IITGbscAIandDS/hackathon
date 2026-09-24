# 🛡️ AEGIS-7: Autonomous Fraud Intelligence Engine

An agentic fraud investigation system built with Python and graph-based intelligence. AEGIS-7 autonomously ingests suspicious financial events, traverses transaction graphs, evaluates risk profiles, and executes next-best actions with full audit trails.

---

## ✨ Features

- **Agentic Decision Pipeline**: Multi-step automated reasoning for real-time fraud assessment.
- **Graph Traversal Engine**: Analyzes accounts, devices, and transfer chains to uncover layering schemes.
- **Explainable AI Audit Logs**: Generates step-by-step audit logs for compliance and human-in-the-loop signoffs.
- **Automated Next-Best Actions**: Applies execution verdicts (e.g., flag account, dismiss false positives, or route to Tier-2 analyst).

---

## 🛠️ Project Structure

```text
fraud-investigator-agent/
├── main.py                     # Entry point & benchmark execution runner
├── agent.py                    # Core agentic reasoning logic
├── graph_client.py             # Subgraph builder & graph query interface
├── benchmark_cases.json        # Test suite & evaluation cases
├── schema.gsql                 # Graph database schema
└── requirements.txt            # Python dependencies