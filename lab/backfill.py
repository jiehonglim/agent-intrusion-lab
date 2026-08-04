"""
backfill.py — Schedule manual rule runs over the campaign window so alerts are
materialised before attendees arrive.
"""

from __future__ import annotations

import argparse
import time
from datetime import datetime, timezone
from typing import Optional

from .esclient import kibana_request, load_env, make_es_client
from .rules import ARTICLE_RULES, resolve_rule_ids, get_enabled_rule_so_ids

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CHUNK_SIZE = 50  # Conservative; API max is 100


def _ms_to_iso(ms: int) -> str:
    """Convert epoch milliseconds to ISO8601 UTC string with Z suffix."""
    dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_backfill(
    api_key: str,
    kibana_url: str,
    campaign_start_ms: int,
    campaign_end_ms: int,
) -> int:
    """
    Resolve all non-correlation ARTICLE_RULES to saved-object ids and schedule a
    manual rule run over the campaign window via the bulk_action "run" action.

    Rules where beat=="correlation" are excluded — they query .alerts-* and must
    run after the base rules have already produced alerts.

    Parameters
    ----------
    api_key:
        Elastic API key.
    kibana_url:
        Base Kibana URL.
    campaign_start_ms:
        Campaign window start as epoch milliseconds.
    campaign_end_ms:
        Campaign window end as epoch milliseconds.

    Returns
    -------
    Total number of rules for which a backfill run was scheduled.
    """
    non_correlation_rule_ids = [
        r["rule_id"]
        for r in ARTICLE_RULES
        if r.get("beat") != "correlation"
    ]

    resolved = resolve_rule_ids(non_correlation_rule_ids, api_key=api_key, kibana_url=kibana_url)
    so_ids = [so_id for so_id in resolved.values() if so_id is not None]

    if not so_ids:
        print("No rules resolved to saved-object ids — nothing to backfill.")
        return 0

    start_iso = _ms_to_iso(campaign_start_ms)
    end_iso = _ms_to_iso(campaign_end_ms)

    bulk_path = "/api/detection_engine/rules/_bulk_action"
    total_scheduled = 0

    import requests as _requests

    for chunk_start in range(0, len(so_ids), _CHUNK_SIZE):
        chunk = so_ids[chunk_start: chunk_start + _CHUNK_SIZE]
        body = {
            "action": "run",
            "ids": chunk,
            "run": {
                "start_date": start_iso,
                "end_date": end_iso,
            },
        }
        try:
            kibana_request(
                "POST",
                bulk_path,
                api_key=api_key,
                kibana_url=kibana_url,
                json_body=body,
                public=True,
                unversioned=False,
            )
            total_scheduled += len(chunk)
        except _requests.HTTPError as exc:
            # Kibana returns 500 for partial failures — some rules may have been
            # scheduled successfully while others were disabled. Extract the
            # partial results from the response body before reporting failure.
            partial = 0
            try:
                resp_body = exc.response.json()
                attrs = resp_body.get("attributes", {})
                updated = attrs.get("results", {}).get("updated", [])
                partial = len(updated)
                for err_entry in attrs.get("errors", []):
                    disabled = err_entry.get("rules", [])
                    names = ", ".join(r["name"] for r in disabled[:3])
                    suffix = "..." if len(disabled) > 3 else ""
                    print(f"  SKIP (disabled): {names}{suffix}")
            except Exception:
                pass
            if partial:
                print(
                    f"  Partially succeeded: {partial}/{len(chunk)} rules scheduled "
                    f"(chunk [{chunk_start}:{chunk_start + len(chunk)}])."
                )
                total_scheduled += partial
            else:
                print(
                    f"WARNING: bulk_action run failed for chunk "
                    f"[{chunk_start}:{chunk_start + len(chunk)}]: {exc}"
                )
        except Exception as exc:
            print(
                f"WARNING: bulk_action run failed for chunk "
                f"[{chunk_start}:{chunk_start + len(chunk)}]: {exc}"
            )

    print(f"Scheduled backfill for {total_scheduled} rules over {start_iso} -> {end_iso}")
    return total_scheduled


def poll_alert_count(
    api_key: str,
    es_host: str,
    campaign_start_ms: int,
    campaign_end_ms: int,
    timeout_s: int = 300,
) -> int:
    """
    Poll .alerts-security.alerts-* via ES|QL until count >= 10 or timeout.
    Uses the Elasticsearch client directly (not Kibana) for ES|QL.
    """
    start_iso = _ms_to_iso(campaign_start_ms)
    end_iso = _ms_to_iso(campaign_end_ms)

    esql_query = (
        f'FROM .alerts-security.alerts-* METADATA _index | '
        f'WHERE @timestamp >= "{start_iso}" AND @timestamp <= "{end_iso}" | '
        f'STATS count = COUNT(*) | '
        f'KEEP count'
    )

    es = make_es_client(es_host, api_key)
    deadline = time.monotonic() + timeout_s
    poll_interval = 30
    last_count = 0

    while True:
        try:
            resp = es.esql.query(query=esql_query, format="json")
            values = resp.get("values", [])
            last_count = int(values[0][0]) if values and values[0] else 0
        except Exception as exc:
            print(f"WARNING: ES|QL poll failed: {exc}")
            last_count = 0

        print(f"Alert count: {last_count}")

        if last_count >= 10:
            return last_count

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            print(f"Timeout reached after {timeout_s}s. Final alert count: {last_count}")
            return last_count

        time.sleep(min(poll_interval, remaining))


def run(
    api_key: str,
    kibana_url: str,
    campaign_start_ms: int,
    campaign_end_ms: int,
    es_host: Optional[str] = None,
) -> int:
    """
    Orchestrate backfill scheduling followed by alert count polling.

    Returns the final alert count.
    """
    run_backfill(api_key, kibana_url, campaign_start_ms, campaign_end_ms)
    if es_host:
        return poll_alert_count(api_key, es_host, campaign_start_ms, campaign_end_ms)
    print("Skipping alert poll (no ES_HOST provided).")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Schedule backfill rule runs over the campaign window and wait for alerts."
    )
    parser.add_argument(
        "--api-key",
        required=True,
        help="Elastic API key (raw base64 id:secret string).",
    )
    parser.add_argument(
        "--kibana-url",
        required=True,
        help="Base URL of Kibana, e.g. https://my.kb.elastic.cloud.",
    )
    parser.add_argument(
        "--campaign-start-ms",
        type=int,
        required=True,
        help="Campaign window start as epoch milliseconds.",
    )
    parser.add_argument(
        "--campaign-end-ms",
        type=int,
        required=True,
        help="Campaign window end as epoch milliseconds.",
    )
    return parser


def main() -> None:
    parser = _build_parser()
    # Make all args optional; fall back to env + workshop-meta
    for action in parser._actions:
        if action.required:
            action.required = False
    args = parser.parse_args()

    env = load_env()
    api_key = args.api_key or env.get("ES_API_KEY")
    kibana_url = args.kibana_url or env.get("KIBANA_URL")

    if not api_key:
        parser.error("ES_API_KEY required (--api-key or env var)")
    if not kibana_url:
        parser.error("KIBANA_URL required (--kibana-url or env var)")

    campaign_start_ms = args.campaign_start_ms
    campaign_end_ms = args.campaign_end_ms

    # Read campaign times from workshop-meta if not provided
    if not campaign_start_ms or not campaign_end_ms:
        from .esclient import make_es_client
        es = make_es_client(env["ES_HOST"], api_key)
        try:
            meta = es.search(index="workshop-meta", size=1)
            src = meta["hits"]["hits"][0]["_source"]
            campaign_start_ms = campaign_start_ms or src["campaign_start_ms"]
            campaign_end_ms = campaign_end_ms or src["campaign_end_ms"]
            print(f"Campaign from workshop-meta: {src.get('campaign_start_human')} → {src.get('campaign_end_human')} UTC")
        except Exception as exc:
            parser.error(f"--campaign-start-ms and --campaign-end-ms required (workshop-meta not found: {exc})")

    run(
        api_key=api_key,
        kibana_url=kibana_url,
        campaign_start_ms=int(campaign_start_ms),
        campaign_end_ms=int(campaign_end_ms),
        es_host=env.get("ES_HOST"),
    )


if __name__ == "__main__":
    main()
