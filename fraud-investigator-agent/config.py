import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()

@dataclass(frozen=True)
class Settings:
    # TigerGraph connection details
    TG_HOST: str = os.getenv("TG_HOST", "http://127.0.0.1")
    TG_GRAPH: str = os.getenv("TG_GRAPH", "FraudGraph")
    TG_USERNAME: str = os.getenv("TG_USERNAME", "tigergraph")
    TG_PASSWORD: str = os.getenv("TG_PASSWORD", "tigergraph")
    TG_SECRET: str = os.getenv("TG_SECRET", "")
    
    # Decision thresholds
    HIGH_RISK_THRESHOLD: float = 0.78
    SUSPICIOUS_RISK_THRESHOLD: float = 0.45
    BURST_WINDOW_HOURS: int = 24
    RAPID_TRANSFER_AMOUNT_THRESHOLD: float = 9500.0  # Just below currency reporting limits

settings = Settings()