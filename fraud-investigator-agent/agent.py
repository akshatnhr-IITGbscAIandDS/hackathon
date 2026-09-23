import logging
from typing import Dict, Any, List
from pydantic import BaseModel, Field
from config import settings
from graph_client import TigerGraphFraudClient

logger = logging.getLogger("fraud_agent.engine")

class InvestigationCase(BaseModel):
    case_id: str
    target_user: str
    target_account: str
    initial_risk_score: float
    trigger_reason: str
    
    # Internal agent scratchpad state
    graph_evidence: Dict[str, Any] = Field(default_factory=dict)
    detected_violations: List[str] = Field(default_factory=list)
    uncertainty_level: str = "LOW"  # LOW, MODERATE, HIGH
    recommended_action: str = ""
    requires_human_approval: bool = False
    audit_log: List[str] = Field(default_factory=list)
    final_verdict: str = "PENDING"

class FraudInvestigatorAgent:
    def __init__(self, graph_client: TigerGraphFraudClient):
        self.graph = graph_client

    def investigate(self, case: InvestigationCase) -> InvestigationCase:
        case.audit_log.append(f"Step 1 [Trigger Intake]: Opened case {case.case_id} for user {case.target_user}. Trigger: '{case.trigger_reason}' (Score: {case.initial_risk_score}).")
        
        # Step 2: Evidence Gathering via Graph Analytics
        infra_evidence = self.graph.get_shared_infrastructure(case.target_user)
        transfer_chain = self.graph.trace_money_chain(case.target_account)
        case.graph_evidence = {
            "infrastructure": infra_evidence,
            "transfers": transfer_chain
        }
        case.audit_log.append(f"Step 2 [Graph Evidence]: Found {len(infra_evidence.get('connected_peer_users', []))} connected users and a transfer chain of length {len(transfer_chain)}.")

        # Step 3: Policy Checking & Pattern Recognition
        if len(transfer_chain) >= 2:
            amounts = [tx["amount"] for tx in transfer_chain]
            if all(amt > settings.RAPID_TRANSFER_AMOUNT_THRESHOLD for amt in amounts):
                case.detected_violations.append("RAPID_LAYERING_STRUCTURING: Multiple back-to-back high-value transfers detected.")

        if infra_evidence.get("known_bad_actors_in_cluster"):
            case.detected_violations.append(f"SYNDICATE_LINK: User shares devices/IPs with known flagged users: {infra_evidence['known_bad_actors_in_cluster']}.")

        case.audit_log.append(f"Step 3 [Policy Check]: Detected violations: {case.detected_violations or 'None'}.")

        # Step 4: Uncertainty Assessment
        if settings.SUSPICIOUS_RISK_THRESHOLD <= case.initial_risk_score <= settings.HIGH_RISK_THRESHOLD:
            if not case.detected_violations:
                case.uncertainty_level = "HIGH"
            else:
                case.uncertainty_level = "MODERATE"
        elif case.initial_risk_score > settings.HIGH_RISK_THRESHOLD:
            case.uncertainty_level = "LOW"
        else:
            case.uncertainty_level = "LOW"

        case.audit_log.append(f"Step 4 [Uncertainty Check]: Evaluation assessed uncertainty level as {case.uncertainty_level}.")

        # Step 5: Next-Best Action (NBA) Selection
        if "SYNDICATE_LINK" in " ".join(case.detected_violations) and "RAPID_LAYERING" in " ".join(case.detected_violations):
            case.recommended_action = "FREEZE_ACCOUNT_AND_HALT_OUTBOUND_TRANSFERS"
            case.requires_human_approval = True
        elif case.uncertainty_level == "HIGH":
            case.recommended_action = "STEP_UP_AUTHENTICATION_AND_REQUEST_ID"
            case.requires_human_approval = False
        elif case.initial_risk_score > settings.HIGH_RISK_THRESHOLD:
            case.recommended_action = "RESTRICT_HIGH_VALUE_WITHDRAWALS"
            case.requires_human_approval = True
        else:
            case.recommended_action = "CLOSE_CASE_FALSE_POSITIVE"
            case.requires_human_approval = False

        case.audit_log.append(f"Step 5 [Next-Best Action]: Decision Engine selected: {case.recommended_action}.")

        # Step 6: Approval Routing (Human-in-the-Loop)
        if case.requires_human_approval:
            case.audit_log.append("Step 6 [Approval Routing]: High financial/account impact. Escalated to Tier-2 Fraud Lead for sign-off.")
        else:
            case.audit_log.append("Step 6 [Approval Routing]: Automated straight-through execution permitted under policy threshold.")

        # Step 7: Action Execution
        self._execute_action(case)
        case.audit_log.append(f"Step 7 [Execution]: Executed action dispatch: {case.final_verdict}.")

        # Step 8: Case Memory Update & Explanation
        case.audit_log.append("Step 8 [Case Memory]: Case history committed to audit repository and graph vertex attributes updated.")
        return case

    def _execute_action(self, case: InvestigationCase):
        """Simulates enforcement hooks into transactional processing systems."""
        if case.recommended_action.startswith("FREEZE"):
            case.final_verdict = "ACTION_APPLIED: ACCOUNT_FROZEN_PENDING_REVIEW"
        elif case.recommended_action.startswith("STEP_UP"):
            case.final_verdict = "ACTION_APPLIED: 2FA_CHALLENGE_ISSUED"
        elif case.recommended_action.startswith("RESTRICT"):
            case.final_verdict = "ACTION_APPLIED: DAILY_LIMIT_CAPPED_AT_ZERO"
        else:
            case.final_verdict = "ACTION_APPLIED: DISMISSED_NO_FURTHER_ACTION"