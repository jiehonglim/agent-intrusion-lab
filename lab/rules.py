"""
rules.py – SIEM rule definitions and management for the HF breach lab.

36 rules from the Elastic Security Labs article on the HuggingFace breach.
"""

from __future__ import annotations

import time
from typing import Optional

from . import esclient  # noqa: F401 – imported for callers; used via helpers below
from .esclient import kibana_get, kibana_post

ARTICLE_RULES = [
    # Kubernetes audit_logs rules
    {"rule_id": "7e3f9a2b-1c4d-5e6f-8a0b-9c8d7e6f5a4b", "name": "Kubernetes Secrets List Across Cluster or Sensitive Namespaces", "type": "query", "beat": "secret_list"},
    {"rule_id": "b4c8e2a1-9f3d-4e7c-a2b1-0d5e6f7a8b9c", "name": "Kubernetes Rapid Secret GET Activity Against Multiple Objects", "type": "esql", "beat": "secret_burst"},
    {"rule_id": "4b77d382-b78e-4aae-85a0-8841b80e4fc4", "name": "Kubernetes Forbidden Request from Unusual User Agent", "type": "new_terms", "beat": "denial_storm"},
    {"rule_id": "ec81962e-4bc8-48e6-bfb0-545fc97d8f6a", "name": "Kubernetes Forbidden Creation Request", "type": "eql", "beat": "denial_storm"},
    {"rule_id": "7164081a-3930-11ed-a261-0242ac120002", "name": "Kubernetes Container Created with Excessive Linux Capabilities", "type": "query", "beat": "privileged_pod"},
    {"rule_id": "df7fda76-c92b-4943-bc68-04460a5ea5ba", "name": "Kubernetes Pod Created With HostPID", "type": "query", "beat": "privileged_pod"},
    {"rule_id": "78c6559d-47a7-4f30-91fe-7e2e983206c2", "name": "Unusual Kubernetes Sensitive Workload Modification", "type": "new_terms", "beat": "privileged_pod"},
    {"rule_id": "63c057cc-339a-11ed-a261-0242ac120002", "name": "Kubernetes Anonymous Request Authorized by Unusual User Agent", "type": "new_terms", "beat": "recon"},
    {"rule_id": "a4c8e901-2b7f-4d6e-9a3c-8e1f0d5b6c2a", "name": "Kubernetes Secret get or list with Suspicious User Agent", "type": "query", "beat": "secret_list"},
    {"rule_id": "f8a31c62-0d4e-4b9a-b7e1-6c2a9d4e8f10", "name": "Kubernetes Secret get or list from Node or Pod Service Account", "type": "query", "beat": "secret_list"},
    {"rule_id": "4df91789-7859-4bc4-9c5a-6b56bfa81a8b", "name": "Kubernetes Service Account Token Created via TokenRequest API", "type": "query", "beat": "sa_token"},
    {"rule_id": "12a2f15d-597e-4334-88ff-38a02cb1330b", "name": "Kubernetes Suspicious Self-Subject Review via Unusual User Agent", "type": "new_terms", "beat": "self_subject_review"},
    {"rule_id": "63c056a0-339a-11ed-a261-0242ac120002", "name": "Kubernetes Denied Service Account Request via Unusual User Agent", "type": "new_terms", "beat": "denial_storm"},
    {"rule_id": "c2a91e88-4f4b-4e1d-9c7b-8fde112a9403", "name": "Kubernetes Multi-Resource Discovery", "type": "esql", "beat": "multi_resource_discovery"},
    {"rule_id": "c7908cac-337a-4f38-b50d-5eeb78bdb531", "name": "Kubernetes Privileged Pod Created", "type": "query", "beat": "privileged_pod"},
    {"rule_id": "2abda169-416b-4bb3-9a6b-f8d239fd78ba", "name": "Kubernetes Pod Created with a Sensitive hostPath Volume", "type": "query", "beat": "privileged_pod"},
    {"rule_id": "a8e7d6c5-b4a3-2918-0f9e-8d7c6b5a4032", "name": "Kubernetes Pod Exec Cloud Instance Metadata Access", "type": "esql", "beat": "imds_harvest"},
    {"rule_id": "a2951930-dd35-438c-b10e-1bbdc5881cb4", "name": "Kubernetes Cluster-Admin Role Binding Created", "type": "query", "beat": "cluster_admin"},
    {"rule_id": "14de811c-d60f-11ec-9fd7-f661ea17fbce", "name": "Kubernetes User Exec into Pod", "type": "eql", "beat": "exec_into_pod"},
    # AWS CloudTrail rules
    {"rule_id": "30fbf4db-c502-4e68-a239-2e99af0f70da", "name": "AWS STS GetCallerIdentity API Called for the First Time", "type": "new_terms", "beat": "aws_sts_identity"},
    {"rule_id": "d1b37c0b-4f8b-4cfb-9a1d-639bf8c028b7", "name": "AWS Rare Source AS Organization Activity", "type": "esql", "beat": "aws_discovery"},
    {"rule_id": "9f8e3c5e-f72e-4e91-93f6-e98a4fae3e4f", "name": "AWS IAM Long-Term Access Key First Seen from Source IP", "type": "new_terms", "beat": "aws_new_ip"},
    {"rule_id": "0d92d30a-5f3e-4b71-bc3d-4a0c4914b7e0", "name": "AWS Access Token Used from Multiple Addresses", "type": "esql", "beat": "credential_replay"},
    {"rule_id": "b2f8c4e1-6a73-4f1e-9c2d-8e5b0a1d3f7c", "name": "AWS EC2 Role GetCallerIdentity from New Source AS Organization", "type": "new_terms", "beat": "aws_new_ip"},
    {"rule_id": "a1b2c3d4-e5f6-4789-a0b1-c2d3e4f5a6b7", "name": "AWS Lateral Movement from Kubernetes SA via AssumeRoleWithWebIdentity", "type": "esql", "beat": "aws_sa_pivot"},
    {"rule_id": "ae32268b-bfd0-4c35-b002-13461b5830ca", "name": "AWS AssumeRoleWithWebIdentity from Kubernetes SA and External ASN", "type": "query", "beat": "aws_sa_pivot"},
    {"rule_id": "74f45152-9aee-11ef-b0a5-f661ea17fbcd", "name": "AWS Discovery API Calls via CLI from a Single Resource", "type": "esql", "beat": "aws_discovery"},
    # Endpoint process rules
    {"rule_id": "f16fca20-4d6c-43f9-aec1-20b6de3b0aeb", "name": "Suspicious Child Execution via Web Server", "type": "eql", "beat": "rce_spawn"},
    {"rule_id": "d9af2479-ad13-4471-a312-f586517f1243", "name": "Curl or Wget Spawned via Node.js", "type": "eql", "beat": "rce_spawn"},
    {"rule_id": "b53f1d73-150d-484d-8f02-222abeb5d5fa", "name": "Kubernetes Direct API Request via Curl or Wget", "type": "eql", "beat": "rce_spawn"},
    # Endpoint network rules
    {"rule_id": "4ae94fc1-f08f-419f-b692-053d28219380", "name": "Connection to Common Large Language Model Endpoints", "type": "eql", "beat": "llm_c2"},
    {"rule_id": "9050506c-df6d-4bdf-bc82-fcad0ef1e8c1", "name": "GenAI Process Connection to Unusual Domain", "type": "new_terms", "beat": "c2_domain"},
    {"rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890", "name": "GenAI Process Connection to Suspicious Top Level Domain", "type": "eql", "beat": "c2_domain"},
    # Endpoint file rules
    {"rule_id": "c0136397-f82a-45e5-9b9f-a3651d77e21a", "name": "GenAI Process Accessing Sensitive Files", "type": "eql", "beat": "credential_access"},
    # Correlation rules (run AFTER backfill)
    {"rule_id": "d4e5f6a7-b8c9-7d0e-1f2a-3b4c5d6e7f8a", "name": "Elastic Defend Alert from GenAI Utility or Descendant", "type": "esql", "beat": "correlation"},
    {"rule_id": "f236cca1-e887-4d14-9ba9-bb8dd3e16cf1", "name": "LLM-Based Attack Chain Triage by Host", "type": "esql", "beat": "correlation"},
]

# Correlation rules query .alerts-* and do not need to be resolved to SO ids
# before backfill; skip them in get_enabled_rule_so_ids.
_CORRELATION_BEATS = {"correlation"}


def install_prebuilt_rules(api_key: str, kibana_url: str) -> dict:
    """
    Install all available prebuilt Elastic Security detection rules.

    1. GET /internal/detection_engine/prebuilt_rules/status
    2. If rules are available, POST to perform installation with mode ALL_RULES
    3. Poll status until num_prebuilt_rules_to_install == 0 (every 10 s, timeout 600 s)

    Returns the final status stats dict.
    """
    status_path = "/internal/detection_engine/prebuilt_rules/status"
    install_path = "/internal/detection_engine/prebuilt_rules/installation/_perform"

    raw = kibana_get(status_path, api_key=api_key, kibana_url=kibana_url, public=False)
    # Response shape: {"stats": {"num_prebuilt_rules_to_install": N, ...}, ...}
    status = raw.get("stats", raw) if isinstance(raw, dict) else raw

    to_install = status.get("num_prebuilt_rules_to_install", 0)
    total = status.get("num_prebuilt_rules_total_in_package", to_install)

    if to_install == 0:
        print(f"All prebuilt rules already installed ({total} total).")
        return status

    print(f"Installing {to_install} prebuilt rules (total in package: {total}) …")

    kibana_post(
        install_path,
        body={"mode": "ALL_RULES"},
        api_key=api_key,
        kibana_url=kibana_url,
        public=False,
        timeout=300,
    )

    deadline = time.time() + 600
    poll_interval = 10

    while time.time() < deadline:
        time.sleep(poll_interval)
        raw = kibana_get(status_path, api_key=api_key, kibana_url=kibana_url, public=False)
        status = raw.get("stats", raw) if isinstance(raw, dict) else raw
        remaining = status.get("num_prebuilt_rules_to_install", 0)
        installed_so_far = to_install - remaining
        print(f"Installed: {installed_so_far}/{to_install}")
        if remaining == 0:
            print("All prebuilt rules installed successfully.")
            return status

    raise TimeoutError(
        f"Prebuilt rule installation did not complete within 600 s. "
        f"Last status: {status}"
    )


def resolve_rule_ids(
    rule_ids: list[str],
    api_key: str,
    kibana_url: str,
) -> dict[str, Optional[str]]:
    """
    Resolve detection rule_ids (UUIDs from the article) to Kibana saved-object ids.

    GET /api/detection_engine/rules?rule_id={rule_id} for each id.
    Returns {rule_id -> so_id | None}.  Rules not found get None + a warning.
    Batches requests in groups of 10 with a 0.5 s pause between batches.
    """
    result: dict[str, Optional[str]] = {}
    batch_size = 10

    for batch_start in range(0, len(rule_ids), batch_size):
        batch = rule_ids[batch_start : batch_start + batch_size]

        for rule_id in batch:
            try:
                rule = kibana_get(
                    f"/api/detection_engine/rules?rule_id={rule_id}",
                    api_key=api_key,
                    kibana_url=kibana_url,
                )
                so_id = rule.get("id")
                if so_id:
                    result[rule_id] = so_id
                else:
                    print(f"WARNING: rule_id {rule_id!r} returned no 'id' field.")
                    result[rule_id] = None
            except Exception as exc:
                status_code = getattr(exc, "status_code", None)
                if status_code == 404 or "404" in str(exc):
                    print(f"WARNING: rule_id {rule_id!r} not found (404).")
                    result[rule_id] = None
                else:
                    print(f"WARNING: error resolving rule_id {rule_id!r}: {exc}")
                    result[rule_id] = None

        # Avoid hammering the API between batches
        if batch_start + batch_size < len(rule_ids):
            time.sleep(0.5)

    return result


def enable_rules(
    so_ids: list[str],
    api_key: str,
    kibana_url: str,
    tag: str = "workshop-wai",
) -> int:
    """
    Tag and enable a list of rules identified by their Kibana saved-object ids.

    1. Add *tag* to all rules via _bulk_action edit.
    2. Enable all rules via _bulk_action enable.
    Batches in chunks of 100.

    Returns the total count of successfully enabled rules.
    """
    bulk_path = "/api/detection_engine/rules/_bulk_action"
    chunk_size = 100
    enabled_count = 0

    for chunk_start in range(0, len(so_ids), chunk_size):
        chunk = so_ids[chunk_start : chunk_start + chunk_size]

        # Step 1 – add workshop tag
        try:
            kibana_post(
                bulk_path,
                body={
                    "action": "edit",
                    "ids": chunk,
                    "edit": [{"type": "add_tags", "value": [tag]}],
                },
                api_key=api_key,
                kibana_url=kibana_url,
            )
        except Exception as exc:
            print(
                f"WARNING: failed to tag chunk [{chunk_start}:{chunk_start + len(chunk)}]: {exc}"
            )

        # Step 2 – enable
        try:
            resp = kibana_post(
                bulk_path,
                body={"action": "enable", "ids": chunk},
                api_key=api_key,
                kibana_url=kibana_url,
            )
            # The bulk action response includes counts under attributes.summary
            summary = (resp or {}).get("attributes", {}).get("summary", {})
            chunk_enabled = summary.get("succeeded", len(chunk))
            enabled_count += chunk_enabled
            print(
                f"Enabled chunk [{chunk_start}:{chunk_start + len(chunk)}]: "
                f"{chunk_enabled} rules."
            )
        except Exception as exc:
            print(
                f"WARNING: failed to enable chunk [{chunk_start}:{chunk_start + len(chunk)}]: {exc}"
            )

    return enabled_count


def get_enabled_rule_so_ids(api_key: str, kibana_url: str) -> list[str]:
    """
    Resolve all ARTICLE_RULES rule_ids to Kibana saved-object ids, skipping
    correlation rules (beat in _CORRELATION_BEATS) which target .alerts-* indices
    and do not need to be resolved before backfill.

    Returns the list of resolved SO ids (None values filtered out).
    """
    non_correlation_rules = [
        r for r in ARTICLE_RULES if r.get("beat") not in _CORRELATION_BEATS
    ]

    rule_ids = [r["rule_id"] for r in non_correlation_rules]

    resolved = resolve_rule_ids(rule_ids, api_key=api_key, kibana_url=kibana_url)

    return [so_id for so_id in resolved.values() if so_id is not None]


if __name__ == "__main__":
    import argparse
    from .esclient import load_env

    parser = argparse.ArgumentParser(description="Install and enable prebuilt rules for agent-intrusion-lab")
    parser.add_argument("--host", default=None)
    parser.add_argument("--api-key", default=None, dest="api_key")
    parser.add_argument("--kibana-url", default=None, dest="kibana_url")
    parser.add_argument("--skip-enable", action="store_true", dest="skip_enable")
    args = parser.parse_args()

    env = load_env()
    api_key = args.api_key or env.get("ES_API_KEY")
    kibana_url = args.kibana_url or env.get("KIBANA_URL")

    if not api_key:
        raise SystemExit("ES_API_KEY required")
    if not kibana_url:
        raise SystemExit("KIBANA_URL required")

    print("[1] Installing prebuilt rules...")
    stats = install_prebuilt_rules(api_key, kibana_url)
    print(f"    Prebuilt rules installed: {stats}")

    if not args.skip_enable:
        print(f"[2] Resolving {len(ARTICLE_RULES)} article rules...")
        rule_ids = [r["rule_id"] for r in ARTICLE_RULES]
        resolved = resolve_rule_ids(rule_ids, api_key=api_key, kibana_url=kibana_url)
        so_ids = [sid for sid in resolved.values() if sid]
        missing = [rid for rid, sid in resolved.items() if not sid]
        if missing:
            print(f"    WARNING: {len(missing)} rule_ids not found on this cluster")
            for rid in missing:
                print(f"      - {rid}")
        print(f"[3] Enabling {len(so_ids)} rules...")
        enabled = enable_rules(so_ids, api_key=api_key, kibana_url=kibana_url)
        print(f"    Enabled: {enabled} rules")
