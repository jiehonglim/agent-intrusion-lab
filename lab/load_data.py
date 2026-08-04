import argparse
import random
import time
import uuid
from datetime import datetime, timezone

from elasticsearch import helpers

from .campaign import attack_docs
from .confounders import confounder_docs
from .noise import noise_docs
from .schema import install_schema, DATA_STREAMS, DS_NAMESPACE
from .esclient import make_es_client, load_env

SEED = 20260709
TOTAL_TARGET = 330_000


def compute_anchor_ms():
    now = datetime.now(timezone.utc)
    anchor_dt = now.replace(hour=0, minute=0, second=0, microsecond=0)
    anchor_ms = int(anchor_dt.timestamp() * 1000)

    campaign_start_ms = anchor_ms - 7 * 86400 * 1000 + 2 * 3600 * 1000
    campaign_end_ms = anchor_ms - 2 * 86400 * 1000 + 13 * 3600 * 1000 + 37 * 60 * 1000

    start_dt = datetime.fromtimestamp(campaign_start_ms / 1000, tz=timezone.utc)
    end_dt = datetime.fromtimestamp(campaign_end_ms / 1000, tz=timezone.utc)
    print(
        f"Campaign: {start_dt.strftime('%Y-%m-%d %H:%M')} → "
        f"{end_dt.strftime('%Y-%m-%d %H:%M')} UTC"
    )

    return anchor_ms, campaign_start_ms, campaign_end_ms


def all_docs(rng, anchor_ms, total_target, ds_namespace):
    count = 0

    for doc in attack_docs(rng, anchor_ms, ds_namespace):
        doc["_op_type"] = "create"
        yield doc
        count += 1

    for doc in confounder_docs(rng, anchor_ms, ds_namespace):
        doc["_op_type"] = "create"
        yield doc
        count += 1

    remaining = total_target - count
    if remaining > 0:
        for doc in noise_docs(rng, anchor_ms, remaining, ds_namespace):
            doc["_op_type"] = "create"
            yield doc


def load(host, api_key, seed=SEED, total_target=TOTAL_TARGET, bulk_host=None, dry_run=False):
    es = make_es_client(host=host, api_key=api_key)
    bulk_es = make_es_client(host=bulk_host, api_key=api_key) if bulk_host else es

    install_schema(es)

    anchor_ms, campaign_start_ms, campaign_end_ms = compute_anchor_ms()

    rng = random.Random(seed)

    print(f"Seed: {seed}")
    print(f"Total target: {total_target:,}")
    print(f"Dry run: {dry_run}")

    if dry_run:
        print("Counting docs (dry run)...")
        count = 0
        for _ in all_docs(rng, anchor_ms, total_target, DS_NAMESPACE):
            count += 1
        print(f"Dry run complete. Would index {count:,} docs.")
        return

    print("Loading docs...")
    ok = 0
    err = 0
    errors = []
    t0 = time.time()

    gen = all_docs(rng, anchor_ms, total_target, DS_NAMESPACE)

    for success, info in helpers.streaming_bulk(
        bulk_es,
        gen,
        chunk_size=500,
        raise_on_error=False,
    ):
        if success:
            ok += 1
        else:
            err += 1
            if len(errors) < 5:
                errors.append(info)

        total = ok + err
        if total % 10_000 == 0:
            elapsed = time.time() - t0
            rate = total / elapsed if elapsed > 0 else 0
            print(f"  {total:,} docs processed ({ok:,} ok, {err:,} errors) [{rate:.0f} docs/s]")

    elapsed = time.time() - t0
    print(f"Done! {ok:,} docs indexed, {err:,} errors (elapsed: {elapsed:.1f}s)")

    if errors:
        print("First errors:")
        for e in errors:
            print(f"  {e}")

    try:
        meta_doc = {
            "anchor_ms": anchor_ms,
            "campaign_start_ms": campaign_start_ms,
            "campaign_end_ms": campaign_end_ms,
            "total_docs": ok,
            "seed": seed,
            "loaded_at": datetime.now(timezone.utc).isoformat(),
        }
        es.index(index="workshop-meta", body=meta_doc)
        print("Workshop meta doc written.")
    except Exception as exc:
        print(f"Warning: failed to write workshop-meta doc: {exc}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load agent-intrusion-lab historical data")
    parser.add_argument("--host", default=None, help="Elasticsearch host URL")
    parser.add_argument("--api-key", default=None, dest="api_key", help="Elasticsearch API key")
    parser.add_argument("--bulk-host", default=None, dest="bulk_host", help="Separate bulk ingest host URL")
    parser.add_argument("--seed", type=int, default=SEED, help=f"RNG seed (default: {SEED})")
    parser.add_argument("--total-docs", type=int, default=TOTAL_TARGET, dest="total_docs", help=f"Total docs to index (default: {TOTAL_TARGET})")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run", help="Count docs without indexing")
    args = parser.parse_args()

    env = load_env()

    host = args.host or env.get("ES_HOST") or env.get("ELASTICSEARCH_URL")
    api_key = args.api_key or env.get("ES_API_KEY") or env.get("ELASTICSEARCH_API_KEY")

    if not host:
        parser.error("Elasticsearch host required (--host or ES_HOST env var)")
    if not api_key:
        parser.error("Elasticsearch API key required (--api-key or ES_API_KEY env var)")

    load(
        host=host,
        api_key=api_key,
        seed=args.seed,
        total_target=args.total_docs,
        bulk_host=args.bulk_host,
        dry_run=args.dry_run,
    )
