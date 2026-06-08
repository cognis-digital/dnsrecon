# Demo 01 - Basic DNS recon triage

This scenario shows DNSRECON analyzing an exported set of DNS records for
the (fictional) authorized-testing domain `example.com`. All analysis is
**offline**: the tool reads the record file you provide and never resolves
names or touches the network.

## Input

`records.json` is a list of DNS records as you might export them from a
zone file, a `dig`/`drill` dump you converted to JSON, or a DNS provider
API. Each record is `{name, type, value}`.

It deliberately contains several realistic issues:

- `assets.example.com` is a **CNAME to an unclaimed-looking S3 bucket** ->
  subdomain-takeover *candidate* (HIGH). The tool only flags it for manual
  verification; it does not attempt any takeover.
- `blog.example.com` -> GitHub Pages CNAME (takeover candidate).
- The apex has **no DMARC** record and its **SPF ends in `?all`** (neutral).
- A **wildcard** record `*.example.com` is present.
- Only a **single apex NS** is configured.

## Run it

```sh
# Human-readable table
python -m dnsrecon analyze demos/01-basic/records.json

# Machine-readable JSON (for CI / SIEM ingest)
python -m dnsrecon analyze demos/01-basic/records.json --format json

# Gate on high+ severity only
python -m dnsrecon analyze demos/01-basic/records.json --min-severity high
```

## Expected outcome

The command prints the findings and **exits non-zero (1)** because issues
were found, which makes it usable as a CI / pre-deploy gate. Use the
findings as a triage list, then verify each one manually before acting.
