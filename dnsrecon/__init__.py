"""DNSRECON - defensive DNS reconnaissance aggregator.

Analysis/triage/detection only. Parses DNS record data you already
collected (or supply) and surfaces attack-surface hints: dangling
CNAMEs / subdomain-takeover candidates, missing email-auth records
(SPF/DMARC/DKIM-policy), zone-transfer exposure hints, wildcard hints,
and weak/legacy record signals. No active scanning, no exploitation.
"""
from .core import (
    Finding,
    Severity,
    analyze_records,
    load_records,
    parse_records,
    summarize,
    TAKEOVER_FINGERPRINTS,
)

TOOL_NAME = "dnsrecon"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Finding",
    "Severity",
    "analyze_records",
    "load_records",
    "parse_records",
    "summarize",
    "TAKEOVER_FINGERPRINTS",
    "TOOL_NAME",
    "TOOL_VERSION",
]
