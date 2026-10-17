#!/usr/bin/env python3
import argparse
import json
import logging
import os
import re
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

DATA = [
    {
        "id": "aws-access-key-id",
        "provider": "AWS",
        "category": "Cloud",
        "name": "Access Key ID",
        "regex": r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
        "strategy": "prefix",
        "examples": ["AKIAIOSFODNN7EXAMPLE"],
        "non_examples": ["AKIA123"],
        "refs": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_checks.html"],
        "notes": "Standard 20-character AWS access key identifier.",
    },
    {
        "id": "github-pat",
        "provider": "GitHub",
        "category": "Source / CI",
        "name": "Personal Access Token",
        "regex": r"\bghp_[0-9a-zA-Z]{36}\b",
        "strategy": "prefix",
        "examples": ["ghp_" + "a" * 36],
        "non_examples": ["ghp_123"],
        "refs": ["https://github.blog/2021-04-05-updated-secret-scanning-prioritization-and-new-pat-format/"],
        "notes": "GitHub classic personal access token format.",
    },
    {
        "id": "generic-private-key",
        "provider": "Generic",
        "category": "Private Key",
        "name": "RSA/PEM Private Key",
        "regex": r"-----BEGIN [A-Z ]{1,50} PRIVATE KEY-----",
        "strategy": "prefix",
        "examples": ["-----BEGIN RSA PRIVATE KEY-----"],
        "non_examples": ["-----BEGIN CERTIFICATE-----"],
        "refs": ["https://datatracker.ietf.org/doc/html/rfc7468"],
        "notes": "Detects standard PEM-encoded private key headers.",
    },
    {
        "id": "snyk-api-token",
        "provider": "Snyk",
        "category": "Source / CI",
        "name": "API token (UUID)",
        "regex": r"(?i)snyk[\w.\-= :'\"]{0,25}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        "strategy": "keyword",
        "examples": ['snyk_token = "' + "a" * 8 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 4 + "-" + "a" * 12 + '"'],
        "non_examples": ["snyk_token = " + "a" * 20],
        "refs": ["https://docs.snyk.io/snyk-api/snyk-api-authentication"],
        "notes": "UUID-formatted token with keyword gate.",
    },
    {
        "id": "resend-api-key",
        "provider": "Resend",
        "category": "Comms",
        "name": "API key (re_)",
        "regex": r"\bre_[0-9A-Za-z]{32,64}\b",
        "strategy": "prefix",
        "examples": ["re_" + "A" * 36],
        "non_examples": ["re_" + "A" * 10],
        "refs": ["https://resend.com/docs/dashboard/api-keys/introduction"],
        "notes": "Standard re_ prefix followed by high-entropy string.",
    },
    {
        "id": "supabase-api-key",
        "provider": "Supabase",
        "category": "Cloud",
        "name": "API key / Service role key (sbp_)",
        "regex": r"\bsbp_[0-9a-f]{40}\b",
        "strategy": "prefix",
        "examples": ["sbp_" + "a" * 40],
        "non_examples": ["sbp_" + "a" * 10],
        "refs": ["https://supabase.com/docs/guides/cli/getting-started"],
        "notes": "Dedicated CLI access and API tokens.",
    },
    {
        "id": "planetscale-service-token",
        "provider": "PlanetScale",
        "category": "Cloud",
        "name": "Service token secret",
        "regex": r"\bpscale_tkn_[0-9A-Za-z_-]{32,64}\b",
        "strategy": "prefix",
        "examples": ["pscale_tkn_" + "A" * 40],
        "non_examples": ["pscale_tkn_" + "A" * 10],
        "refs": ["https://planetscale.com/docs/concepts/service-tokens"],
        "notes": "Distinctive pscale_tkn_ prefix used for service tokens.",
    },
    {
        "id": "asana-pat",
        "provider": "Asana",
        "category": "Productivity",
        "name": "Personal access token",
        "regex": r"\b[0-9]/[0-9]{16}:[0-9a-f]{32}\b",
        "strategy": "structure",
        "examples": ["1/1200000000000000:" + "a" * 32],
        "non_examples": ["1/1200000000000000:" + "a" * 10],
        "refs": ["https://developers.asana.com/docs/personal-access-token"],
        "notes": "Structured format: 1/<user_id>:<32-hex secret>.",
    },
]


def validate_patterns():
    for entry in DATA:
        try:
            pattern = re.compile(entry["regex"])
        except re.error as e:
            logging.error(f"Invalid regex in pattern '{entry['id']}': {e}")
            raise

        for ex in entry.get("examples", []):
            if not pattern.search(ex):
                raise ValueError(f"Pattern '{entry['id']}' failed matching positive example: {ex}")

        for nex in entry.get("non_examples", []):
            if pattern.search(nex):
                raise ValueError(f"Pattern '{entry['id']}' incorrectly matched negative example: {nex}")


def scan_file_path(file_path: Path, compiled_patterns: list) -> list:
    findings = []
    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, start=1):
                for entry, pattern in compiled_patterns:
                    match = pattern.search(line)
                    if match:
                        matched_str = match.group(0)
                        findings.append({
                            "filename": str(file_path),
                            "line_number": line_num,
                            "matched_string": matched_str,
                            "provider": entry["provider"],
                            "name": entry["name"],
                            "category": entry["category"]
                        })
    except Exception as e:
        logging.warning(f"Could not read file {file_path}: {e}")
    return findings


def scan_target(target_path: str) -> list:
    path = Path(target_path)
    if not path.exists():
        logging.error(f"Target path does not exist: {target_path}")
        return []

    compiled_patterns = [(entry, re.compile(entry["regex"])) for entry in DATA]
    all_findings = []

    if path.is_file():
        logging.info(f"Scanning single file: {path}")
        all_findings.extend(scan_file_path(path, compiled_patterns))
    elif path.is_dir():
        logging.info(f"Scanning directory tree: {path}")
        for root, _, files in os.walk(path):
            # Skip hidden git directories
            if ".git" in root:
                continue
            for file_name in files:
                file_p = Path(root) / file_name
                all_findings.extend(scan_file_path(file_p, compiled_patterns))

    return all_findings


def export_patterns_json(output_file: str = "patterns.json"):
    p = Path(output_file)
    with p.open("w", encoding="utf-8") as f:
        json.dump(DATA, f, indent=4)
    logging.info(f"Exported pattern database to {p.resolve()}")


def main():
    parser = argparse.ArgumentParser(
        description="CLI Tool to scan files or directories for hardcoded secrets."
    )
    parser.add_argument(
        "path",
        type=str,
        help="Path to the file or directory to scan.",
    )
    parser.add_argument(
        "--export-patterns",
        action="store_true",
        help="Export the patterns database to patterns.json before scanning.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output report findings in JSON format.",
    )

    args = parser.parse_args()
    validate_patterns()

    if args.export_patterns:
        export_patterns_json()

    findings = scan_target(args.path)

    print("\n" + "=" * 60)
    print("      SECRET SCANNER FINDINGS REPORT")
    print("=" * 60)

    if args.json:
        print(json.dumps(findings, indent=4))
    else:
        if not findings:
            print("No hardcoded secrets detected.")
        else:
            for item in findings:
                print(f"Filename:       {item['filename']}")
                print(f"Line Number:    {item['line_number']}")
                print(f"Matched String: {item['matched_string']}")
                print(f"Secret Type:    {item['provider']} - {item['name']} ({item['category']})")
                print("-" * 60)

    print(f"\nScan finished. Total findings: {len(findings)}")


if __name__ == "__main__":
    main()