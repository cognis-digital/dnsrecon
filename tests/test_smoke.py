"""Offline smoke tests for DNSRECON (no network)."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dnsrecon import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    Severity,
    analyze_records,
    parse_records,
    summarize,
)
from dnsrecon.cli import main  # noqa: E402


DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic", "records.json")


class TestMeta(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "dnsrecon")
        self.assertTrue(TOOL_VERSION)


class TestEngine(unittest.TestCase):
    def test_takeover_candidate_detected(self):
        recs = parse_records([
            {"name": "x.example.com", "type": "CNAME", "value": "foo.s3.amazonaws.com"},
        ])
        findings = analyze_records(recs)
        rules = {f.rule for f in findings}
        self.assertIn("subdomain_takeover_candidate", rules)
        tk = next(f for f in findings if f.rule == "subdomain_takeover_candidate")
        self.assertEqual(tk.severity, Severity.HIGH)

    def test_github_pages_takeover(self):
        recs = parse_records([
            {"name": "blog.example.com", "type": "CNAME", "value": "acme.github.io."},
        ])
        findings = analyze_records(recs)
        self.assertTrue(any(f.rule == "subdomain_takeover_candidate" for f in findings))

    def test_missing_spf_and_dmarc(self):
        recs = parse_records([
            {"name": "example.com", "type": "A", "value": "203.0.113.1"},
            {"name": "example.com", "type": "MX", "value": "10 mail.example.com."},
        ])
        findings = analyze_records(recs)
        rules = {f.rule for f in findings}
        self.assertIn("missing_spf", rules)
        self.assertIn("missing_dmarc", rules)

    def test_spf_neutral_all_flagged(self):
        recs = parse_records([
            {"name": "example.com", "type": "A", "value": "203.0.113.1"},
            {"name": "example.com", "type": "TXT", "value": "v=spf1 include:_spf.x.net ?all"},
        ])
        findings = analyze_records(recs)
        self.assertTrue(any(f.rule == "spf_neutral_all" for f in findings))

    def test_spf_permissive_all_is_high(self):
        recs = parse_records([
            {"name": "example.com", "type": "A", "value": "203.0.113.1"},
            {"name": "example.com", "type": "TXT", "value": "v=spf1 +all"},
        ])
        findings = analyze_records(recs)
        f = next(x for x in findings if x.rule == "spf_permissive_all")
        self.assertEqual(f.severity, Severity.HIGH)

    def test_wildcard_detected(self):
        recs = parse_records([
            {"name": "*.example.com", "type": "A", "value": "203.0.113.1"},
        ])
        findings = analyze_records(recs)
        self.assertTrue(any(f.rule == "wildcard_record" for f in findings))

    def test_clean_zone_has_no_takeover(self):
        recs = parse_records([
            {"name": "example.com", "type": "A", "value": "203.0.113.1"},
            {"name": "example.com", "type": "NS", "value": "ns1.example.com."},
            {"name": "example.com", "type": "NS", "value": "ns2.example.com."},
            {"name": "example.com", "type": "TXT", "value": "v=spf1 -all"},
            {"name": "_dmarc.example.com", "type": "TXT", "value": "v=DMARC1; p=reject"},
        ])
        findings = analyze_records(recs)
        rules = {f.rule for f in findings}
        self.assertNotIn("subdomain_takeover_candidate", rules)
        self.assertNotIn("missing_spf", rules)
        self.assertNotIn("missing_dmarc", rules)
        self.assertNotIn("single_nameserver", rules)

    def test_summary_shape(self):
        recs = parse_records([
            {"name": "x.example.com", "type": "CNAME", "value": "foo.s3.amazonaws.com"},
        ])
        report = summarize(recs, analyze_records(recs))
        self.assertEqual(report["tool"], "dnsrecon")
        self.assertEqual(report["records_analyzed"], 1)
        self.assertIn("findings", report)
        # round-trips as JSON
        json.dumps(report)

    def test_bad_record_raises(self):
        with self.assertRaises(ValueError):
            parse_records([{"type": "A", "value": "1.2.3.4"}])  # missing name


class TestCLI(unittest.TestCase):
    def test_analyze_demo_json_exits_nonzero(self):
        rc = main(["analyze", DEMO, "--format", "json"])
        self.assertEqual(rc, 1)  # findings present -> non-zero

    def test_analyze_table(self):
        rc = main(["analyze", DEMO, "--format", "table"])
        self.assertEqual(rc, 1)

    def test_min_severity_filter(self):
        rc = main(["analyze", DEMO, "--min-severity", "high"])
        self.assertEqual(rc, 1)

    def test_missing_file_exit_2(self):
        rc = main(["analyze", "/no/such/file.json"])
        self.assertEqual(rc, 2)

    def test_no_command_exit_2(self):
        rc = main([])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
