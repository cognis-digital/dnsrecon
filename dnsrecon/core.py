"""Core DNS recon analysis engine (standard library only).

Input model
-----------
DNS records are supplied as a list of dicts (decoded from JSON) or as a
simple text zone-style file. Each record has:
    name  : owner name (FQDN, e.g. "app.example.com")
    type  : record type (A, AAAA, CNAME, MX, TXT, NS, SOA, ...)
    value : record data (string)

This tool performs purely OFFLINE analysis of that data. It never
resolves names or contacts a network.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from typing import Any, Iterable


class Severity:
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    _ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @classmethod
    def rank(cls, sev: str) -> int:
        return cls._ORDER.get(sev, 0)


# Known service fingerprints whose dangling CNAME targets are classic
# subdomain-takeover candidates. Matching a suffix only FLAGS the record
# for manual verification -- it does not claim or perform a takeover.
TAKEOVER_FINGERPRINTS = {
    "s3.amazonaws.com": "AWS S3 bucket",
    ".cloudfront.net": "AWS CloudFront",
    ".azurewebsites.net": "Azure App Service",
    ".cloudapp.net": "Azure Cloud Service",
    ".trafficmanager.net": "Azure Traffic Manager",
    ".blob.core.windows.net": "Azure Blob Storage",
    ".github.io": "GitHub Pages",
    ".herokuapp.com": "Heroku",
    ".herokudns.com": "Heroku",
    ".ghost.io": "Ghost",
    ".myshopify.com": "Shopify",
    ".wordpress.com": "WordPress",
    ".pantheonsite.io": "Pantheon",
    ".fastly.net": "Fastly",
    ".readme.io": "Readme.io",
    ".surge.sh": "Surge.sh",
    ".bitbucket.io": "Bitbucket",
    ".zendesk.com": "Zendesk",
    ".helpscoutdocs.com": "Help Scout",
    ".statuspage.io": "Statuspage",
    ".unbouncepages.com": "Unbounce",
    ".desk.com": "Desk",
    ".netlify.app": "Netlify",
    ".firebaseapp.com": "Firebase",
}


@dataclass
class Finding:
    rule: str
    severity: str
    name: str
    detail: str
    record_type: str = ""
    value: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Record:
    name: str
    type: str
    value: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.name.lower().rstrip("."), self.type.upper())


def parse_records(data: Iterable[dict[str, Any]]) -> list[Record]:
    """Build Record objects from decoded JSON dicts."""
    recs: list[Record] = []
    for i, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(f"record #{i} is not an object")
        name = str(item.get("name", "")).strip()
        rtype = str(item.get("type", "")).strip().upper()
        value = str(item.get("value", item.get("data", ""))).strip()
        if not name or not rtype:
            raise ValueError(f"record #{i} missing name or type")
        recs.append(Record(name=name, type=rtype, value=value))
    return recs


def _parse_text(text: str) -> list[dict[str, Any]]:
    """Parse a minimal whitespace zone-ish format: NAME TYPE VALUE.

    Lines beginning with '#' or ';' and blank lines are ignored. VALUE
    may contain spaces (everything after the type is the value).
    """
    out: list[dict[str, Any]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in "#;":
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        name = parts[0]
        rtype = parts[1]
        value = parts[2] if len(parts) == 3 else ""
        out.append({"name": name, "type": rtype, "value": value})
    return out


def load_records(path: str) -> list[Record]:
    """Load records from a JSON or text file.

    JSON may be a list of records or {"records": [...]}.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read()
    stripped = raw.lstrip()
    if stripped[:1] in "[{":
        doc = json.loads(raw)
        if isinstance(doc, dict):
            doc = doc.get("records", [])
        if not isinstance(doc, list):
            raise ValueError("JSON must be a list or {'records': [...]}")
        return parse_records(doc)
    return parse_records(_parse_text(raw))


def _has_token(values: list[str], token: str) -> bool:
    token = token.lower()
    return any(token in v.lower() for v in values)


def analyze_records(records: list[Record]) -> list[Finding]:
    """Run all offline detection rules over the record set."""
    findings: list[Finding] = []

    # Index by name for cross-record checks.
    by_name: dict[str, list[Record]] = {}
    for r in records:
        by_name.setdefault(r.name.lower().rstrip("."), []).append(r)

    # Apex = the shortest name present (best-effort heuristic).
    apex = ""
    if by_name:
        apex = min(by_name, key=lambda n: (n.count("."), len(n)))

    # --- Rule: dangling CNAME / subdomain-takeover candidates ---
    for r in records:
        if r.type != "CNAME":
            continue
        target = r.value.lower().rstrip(".")
        for fp, svc in TAKEOVER_FINGERPRINTS.items():
            if target.endswith(fp) or fp in target:
                findings.append(Finding(
                    rule="subdomain_takeover_candidate",
                    severity=Severity.HIGH,
                    name=r.name,
                    record_type="CNAME",
                    value=r.value,
                    detail=(f"CNAME points to {svc} ({fp}). If the backing "
                            "resource is unclaimed/deprovisioned, this name is "
                            "a takeover candidate."),
                    recommendation=("Verify the target resource still exists and "
                                    "is owned by you; remove the record if the "
                                    "service was decommissioned."),
                ))
                break

    # --- Rule: wildcard record exposure hint ---
    for r in records:
        if r.name.startswith("*."):
            findings.append(Finding(
                rule="wildcard_record",
                severity=Severity.LOW,
                name=r.name,
                record_type=r.type,
                value=r.value,
                detail="Wildcard record present; broadens attack surface and "
                       "can mask dangling subdomains.",
                recommendation="Confirm the wildcard is intentional and scoped.",
            ))

    # --- Rule: zone transfer / NS exposure hints (from TXT/SOA markers) ---
    txt_values = [r.value for r in records if r.type == "TXT"]
    ns_count = sum(1 for r in records if r.type == "NS" and r.name.lower().rstrip(".") == apex)
    if apex and ns_count == 1:
        findings.append(Finding(
            rule="single_nameserver",
            severity=Severity.MEDIUM,
            name=apex,
            record_type="NS",
            detail="Only one apex NS record observed; a single nameserver is a "
                   "resilience and availability risk.",
            recommendation="Provision at least two geographically diverse NS.",
        ))

    # --- Email auth rules (apex) ---
    if apex:
        apex_txt = [r.value for r in by_name.get(apex, []) if r.type == "TXT"]
        # SPF
        spf = [v for v in apex_txt if v.lower().startswith("v=spf1")]
        has_mx = any(r.type == "MX" for r in by_name.get(apex, []))
        if not spf:
            findings.append(Finding(
                rule="missing_spf",
                severity=Severity.MEDIUM if has_mx else Severity.LOW,
                name=apex,
                record_type="TXT",
                detail="No SPF (v=spf1) TXT record at apex; domain is easier to "
                       "spoof in email.",
                recommendation="Publish a strict SPF record ending in -all.",
            ))
        else:
            for v in spf:
                low = v.lower()
                if low.rstrip().endswith("+all") or " +all" in low:
                    findings.append(Finding(
                        rule="spf_permissive_all",
                        severity=Severity.HIGH,
                        name=apex,
                        record_type="TXT",
                        value=v,
                        detail="SPF ends in '+all', which authorizes any sender.",
                        recommendation="Change qualifier to -all (or ~all).",
                    ))
                elif low.rstrip().endswith("?all"):
                    findings.append(Finding(
                        rule="spf_neutral_all",
                        severity=Severity.LOW,
                        name=apex,
                        record_type="TXT",
                        value=v,
                        detail="SPF ends in '?all' (neutral); offers no protection.",
                        recommendation="Use -all or ~all instead of ?all.",
                    ))

        # DMARC lives at _dmarc.<apex>
        dmarc_name = f"_dmarc.{apex}"
        dmarc_txt = [r.value for r in by_name.get(dmarc_name, []) if r.type == "TXT"]
        dmarc = [v for v in dmarc_txt if v.lower().startswith("v=dmarc1")]
        if not dmarc:
            findings.append(Finding(
                rule="missing_dmarc",
                severity=Severity.MEDIUM,
                name=dmarc_name,
                record_type="TXT",
                detail="No DMARC record; spoofed mail will not be reported or "
                       "rejected by receivers.",
                recommendation="Publish a DMARC record, starting at p=none for "
                               "monitoring then tightening to p=reject.",
            ))
        else:
            for v in dmarc:
                low = v.lower().replace(" ", "")
                if "p=none" in low:
                    findings.append(Finding(
                        rule="dmarc_policy_none",
                        severity=Severity.LOW,
                        name=dmarc_name,
                        record_type="TXT",
                        value=v,
                        detail="DMARC policy is p=none (monitor only).",
                        recommendation="Progress to p=quarantine then p=reject.",
                    ))

    # --- Rule: legacy/weak signals ---
    for r in records:
        if r.type == "TXT" and r.value.lower().startswith("v=spf1") and "ptr" in r.value.lower():
            findings.append(Finding(
                rule="spf_uses_ptr",
                severity=Severity.LOW,
                name=r.name,
                record_type="TXT",
                value=r.value,
                detail="SPF uses deprecated 'ptr' mechanism (slow, discouraged).",
                recommendation="Replace ptr with ip4/ip6/include mechanisms.",
            ))

    findings.sort(key=lambda f: (-Severity.rank(f.severity), f.rule, f.name))
    return findings


def summarize(records: list[Record], findings: list[Finding]) -> dict[str, Any]:
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    type_counts: dict[str, int] = {}
    for r in records:
        type_counts[r.type] = type_counts.get(r.type, 0) + 1
    return {
        "tool": "dnsrecon",
        "records_analyzed": len(records),
        "record_types": dict(sorted(type_counts.items())),
        "findings_total": len(findings),
        "findings_by_severity": sev_counts,
        "findings": [f.to_dict() for f in findings],
    }
