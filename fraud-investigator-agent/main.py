import json
import logging
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from config import settings
from graph_client import TigerGraphFraudClient
from agent import FraudInvestigatorAgent, InvestigationCase

logging.basicConfig(level=logging.WARNING)
console = Console()

def run_benchmark_evaluations():
    console.print(Panel.fit("[bold cyan]TigerGraph Agentic Fraud Investigation System[/bold cyan]\n[dim]Autonomous Next-Best Action Engine[/dim]"))
    
    # Initialize graph backend
    graph_client = TigerGraphFraudClient(
        host=settings.TG_HOST,
        graphname=settings.TG_GRAPH,
        username=settings.TG_USERNAME,
        password=settings.TG_PASSWORD
    )
    
    agent = FraudInvestigatorAgent(graph_client=graph_client)

    # Load benchmark alerts
    with open("benchmark_cases.json", "r") as f:
        cases_data = json.load(f)

    for item in cases_data:
        case = InvestigationCase(**item)
        console.print(f"\n[bold yellow]>>> Processing Alert: {case.case_id} (User: {case.target_user})[/bold yellow]")
        
        investigated = agent.investigate(case)
        
        # Display Step-by-Step Investigation Trace
        table = Table(title=f"Investigation Trace & Action Report - {investigated.case_id}", show_lines=True)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Details", style="white")

        table.add_row("Target User", investigated.target_user)
        table.add_row("Initial Risk Score", str(investigated.initial_risk_score))
        table.add_row("Detected Graph Violations", "\n".join(investigated.detected_violations) if investigated.detected_violations else "None")
        table.add_row("Uncertainty Assessment", investigated.uncertainty_level)
        table.add_row("Recommended Next-Best Action", f"[bold red]{investigated.recommended_action}[/bold red]")
        table.add_row("Requires Tier-2 Signoff?", "[bold red]YES[/bold red]" if investigated.requires_human_approval else "[green]NO (Automated)[/green]")
        table.add_row("Execution Verdict", investigated.final_verdict)
        
        console.print(table)
        
        with console.status("[dim]Reviewing step audit trail...[/dim]"):
            console.print("[bold]Step Audit Log:[/bold]")
            for log_entry in investigated.audit_log:
                console.print(f"  [dim]•[/dim] {log_entry}")

if __name__ == "__main__":
    run_benchmark_evaluations()