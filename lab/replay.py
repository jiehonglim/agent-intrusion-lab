"""
replay.py — Live-tail emitter for the agent-intrusion-lab workshop.

Re-emits a compressed slice of the attack campaign at "now" so detection
rules keep firing throughout the workshop session.

Usage:
    python -m lab.replay start --host $ES_HOST --api-key $ES_API_KEY
    python -m lab.replay stop
"""

import argparse
import os
import random
import signal
import sys
import threading
import time
from uuid import uuid4

from elasticsearch import helpers

from .campaign import (
    ATTACK_AKID,
    ATTACK_ASN_ORG,
    ATTACK_AWS_ACCOUNT,
    ATTACK_CLUSTER,
    ATTACK_IAM_ARN,
    ATTACK_IPS,
    ATTACK_NAMESPACE,
    ATTACK_REGION,
    ATTACK_SA,
    ATTACK_USER_AGENT,
    SYNTHETIC_IMAGE,
    WORKER_PARENT,
)
from .esclient import load_env, make_es_client

PID_FILE = "/tmp/wai-replay.pid"

_DS_NAMESPACE = "workshop"

# ---------------------------------------------------------------------------
# Helpers — mirror _make_doc / _uid from campaign.py but stamp "now"
# ---------------------------------------------------------------------------


def _uid() -> str:
    return str(uuid4())


def _hex_id(rng, length: int = 12) -> str:
    return "".join(rng.choices("0123456789abcdef", k=length))


def _now_ms() -> int:
    return int(time.time() * 1000)


def _make_doc(dataset: str, source: dict) -> dict:
    """Wrap a source dict in the streaming-bulk envelope, stamped at now."""
    source.setdefault("ecs", {"version": "8.11.0"})
    source["@timestamp"] = _now_ms()
    source.setdefault("event", {})
    source["event"]["dataset"] = dataset
    source["data_stream"] = {
        "type": "logs",
        "dataset": dataset,
        "namespace": _DS_NAMESPACE,
    }
    return {
        "_index": f"logs-{dataset}-{_DS_NAMESPACE}",
        "_op_type": "create",
        "_source": source,
    }


# ---------------------------------------------------------------------------
# Per-thread doc generators (yield one doc per call, stamped at now)
# ---------------------------------------------------------------------------

_K8S_DISCOVERY_RESOURCES = [
    "namespaces", "nodes", "pods", "roles", "configmaps",
    "serviceaccounts", "clusterroles", "clusterrolebindings", "rolebindings",
]

_K8S_CREATE_RESOURCES = [
    "pods", "deployments", "daemonsets", "replicasets",
    "clusterrolebindings", "rolebindings", "services",
]

_AWS_ACTIONS = [
    ("GetCallerIdentity", "sts.amazonaws.com"),
    ("DescribeInstances", "ec2.amazonaws.com"),
    ("ListBuckets", "s3.amazonaws.com"),
    ("ListRoles", "iam.amazonaws.com"),
    ("GetSecretValue", "secretsmanager.amazonaws.com"),
    ("DescribeSubnets", "ec2.amazonaws.com"),
    ("DescribeParameters", "ssm.amazonaws.com"),
]


def _gen_k8s_discovery_doc(rng: random.Random) -> dict:
    """One K8s multi-resource discovery event."""
    dataset = "kubernetes.audit_logs"
    resource = rng.choice(_K8S_DISCOVERY_RESOURCES)
    verb = rng.choice(["list", "get", "watch"])

    if rng.random() < 0.05:
        decision = "forbid"
        outcome = "failure"
    else:
        decision = "allow"
        outcome = "success"

    obj_name = (
        f"{resource[:-1]}-{rng.randint(1, 99):02d}"
        if resource.endswith("s")
        else resource
    )
    request_uri = (
        f"/api/v1/namespaces/{ATTACK_NAMESPACE}/{resource}"
        if resource not in ("namespaces", "nodes", "clusterroles", "clusterrolebindings")
        else f"/api/v1/{resource}"
    )
    if verb == "get":
        request_uri += f"/{obj_name}"

    source = {
        "event": {
            "id": _uid(),
            "action": verb,
            "outcome": outcome,
            "category": ["network", "authentication"],
            "type": ["access"],
        },
        "kubernetes": {
            "audit": {
                "verb": verb,
                "stage": "ResponseComplete",
                "level": "Metadata",
                "requestURI": request_uri,
                "annotations": {
                    "authorization_k8s_io/decision": decision,
                },
                "objectRef": {
                    "resource": resource,
                    "namespace": ATTACK_NAMESPACE,
                    "name": obj_name,
                    "apiVersion": "v1",
                },
                "user": {
                    "username": ATTACK_SA,
                    "groups": ["system:authenticated"],
                },
            },
        },
        "orchestrator": {
            "cluster": {"name": ATTACK_CLUSTER},
            "namespace": ATTACK_NAMESPACE,
            "type": "kubernetes",
        },
        "source": {
            "ip": rng.choice(ATTACK_IPS),
            "as": {
                "organization": {"name": ATTACK_ASN_ORG},
                "number": rng.randint(64512, 65534),
            },
        },
        "user": {"name": ATTACK_SA},
        "user_agent": {"original": ATTACK_USER_AGENT, "name": "python-requests"},
    }
    return _make_doc(dataset, source)


def _gen_k8s_forbidden_creation_doc(rng: random.Random) -> dict:
    """One K8s forbidden creation request event."""
    dataset = "kubernetes.audit_logs"
    resource = rng.choice(_K8S_CREATE_RESOURCES)
    obj_name = f"attack-{resource[:-1]}-{rng.randint(0, 9999):04d}"
    request_uri = (
        f"/apis/apps/v1/namespaces/{ATTACK_NAMESPACE}/{resource}"
        if resource in ("deployments", "daemonsets", "replicasets")
        else f"/api/v1/namespaces/{ATTACK_NAMESPACE}/{resource}"
    )

    source = {
        "event": {
            "id": _uid(),
            "action": "create",
            "outcome": "failure",
            "category": ["network", "authentication"],
            "type": ["access"],
        },
        "kubernetes": {
            "audit": {
                "verb": "create",
                "stage": "ResponseComplete",
                "level": "Request",
                "requestURI": request_uri,
                "annotations": {
                    "authorization_k8s_io/decision": "forbid",
                },
                "objectRef": {
                    "resource": resource,
                    "namespace": ATTACK_NAMESPACE,
                    "name": obj_name,
                    "apiVersion": "v1",
                },
                "user": {
                    "username": ATTACK_SA,
                    "groups": ["system:authenticated"],
                },
            },
        },
        "orchestrator": {
            "cluster": {"name": ATTACK_CLUSTER},
            "namespace": ATTACK_NAMESPACE,
            "type": "kubernetes",
        },
        "source": {
            "ip": rng.choice(ATTACK_IPS),
            "as": {
                "organization": {"name": ATTACK_ASN_ORG},
                "number": rng.randint(64512, 65534),
            },
        },
        "user": {"name": ATTACK_SA},
        "user_agent": {"original": ATTACK_USER_AGENT, "name": "python-requests"},
    }
    return _make_doc(dataset, source)


def _gen_aws_sts_doc(rng: random.Random) -> dict:
    """One AWS STS GetCallerIdentity or discovery call."""
    dataset = "aws.cloudtrail"
    action, provider = rng.choice(_AWS_ACTIONS)
    akid_suffix = rng.randint(10, 99)
    src_ip = rng.choice(ATTACK_IPS)

    source = {
        "event": {
            "id": _uid(),
            "action": action,
            "outcome": "success",
            "provider": provider,
            "category": ["authentication"],
            "type": ["info"],
        },
        "aws": {
            "cloudtrail": {
                "user_identity": {
                    "type": "AssumedRole",
                    "arn": ATTACK_IAM_ARN,
                    "access_key_id": f"ASIAWR4SYNTHETIC{akid_suffix:02d}",
                    "account_id": ATTACK_AWS_ACCOUNT,
                },
                "event_version": "1.08",
                "request_parameters": None,
                "response_elements": None,
            },
        },
        "cloud": {
            "account": {"id": ATTACK_AWS_ACCOUNT},
            "region": ATTACK_REGION,
            "provider": "aws",
        },
        "source": {
            "ip": src_ip,
            "as": {
                "organization": {"name": ATTACK_ASN_ORG},
                "number": rng.randint(64512, 65534),
            },
        },
        "user": {"name": ATTACK_SA},
        "user_agent": {"original": ATTACK_USER_AGENT, "name": "python-requests"},
    }
    return _make_doc(dataset, source)


# ---------------------------------------------------------------------------
# WorkerThread
# ---------------------------------------------------------------------------


class WorkerThread(threading.Thread):
    """
    A daemon thread that emits a fixed pattern of docs at a given rate.

    Parameters
    ----------
    name:
        Human-readable thread name.
    doc_generator:
        Callable(rng) -> dict returning one streaming-bulk document.
    docs_per_minute:
        Emission rate. The thread sleeps (60 / docs_per_minute) seconds
        between single-doc emissions.
    es_client:
        Connected Elasticsearch client.
    stop_event:
        threading.Event; the thread exits when set.
    """

    def __init__(
        self,
        name: str,
        doc_generator,
        docs_per_minute: float,
        es_client,
        stop_event: threading.Event,
    ):
        super().__init__(name=name, daemon=True)
        self._doc_gen = doc_generator
        self._interval = 60.0 / docs_per_minute
        self._es = es_client
        self._stop = stop_event
        self._rng = random.Random()
        self.docs_emitted = 0
        self._lock = threading.Lock()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                doc = self._doc_gen(self._rng)
                # streaming_bulk expects an iterable of actions
                successes, errors = helpers.bulk(
                    self._es,
                    [doc],
                    raise_on_error=False,
                    raise_on_exception=False,
                )
                if successes:
                    with self._lock:
                        self.docs_emitted += successes
                if errors:
                    print(
                        f"[{self.name}] bulk error: {errors[0] if errors else '?'}",
                        file=sys.stderr,
                    )
            except Exception as exc:
                print(f"[{self.name}] exception: {exc}", file=sys.stderr)

            # Wait for the next emission slot, checking stop every 0.5 s
            deadline = time.monotonic() + self._interval
            while not self._stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                time.sleep(min(0.5, remaining))

    @property
    def total_emitted(self) -> int:
        with self._lock:
            return self.docs_emitted


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def start_replay(
    host: str,
    api_key: str,
    bulk_host: str | None = None,
) -> None:
    """
    Create the ES client, spin up 3 worker threads, write the PID file, and
    loop printing stats every 60 s until a stop event is received.

    Thread assignments
    ------------------
    1. K8s multi-resource discovery   — 10 docs/min
    2. K8s forbidden creation requests — 5 docs/min
    3. AWS GetCallerIdentity + discovery — 5 docs/min
    """
    es = make_es_client(host, api_key, bulk_host or None)

    stop_event = threading.Event()

    workers = [
        WorkerThread(
            name="k8s-discovery",
            doc_generator=_gen_k8s_discovery_doc,
            docs_per_minute=10,
            es_client=es,
            stop_event=stop_event,
        ),
        WorkerThread(
            name="k8s-forbidden-create",
            doc_generator=_gen_k8s_forbidden_creation_doc,
            docs_per_minute=5,
            es_client=es,
            stop_event=stop_event,
        ),
        WorkerThread(
            name="aws-sts-discovery",
            doc_generator=_gen_aws_sts_doc,
            docs_per_minute=5,
            es_client=es,
            stop_event=stop_event,
        ),
    ]

    # Write PID file
    pid = os.getpid()
    with open(PID_FILE, "w") as fh:
        fh.write(str(pid))

    # Register signal handlers for graceful shutdown
    def _handle_signal(signum, frame):
        print(f"\n[replay] Received signal {signum}. Shutting down...", flush=True)
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # Start workers
    for w in workers:
        w.start()

    print(
        f"Replay started (PID {pid}). Rules will fire within one interval.",
        flush=True,
    )
    print(
        f"  Threads: {', '.join(w.name for w in workers)}",
        flush=True,
    )

    # Stats loop
    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=60)
            if stop_event.is_set():
                break
            total = sum(w.total_emitted for w in workers)
            parts = ", ".join(f"{w.name}={w.total_emitted}" for w in workers)
            print(f"[replay] docs emitted — total={total} ({parts})", flush=True)
    finally:
        stop_event.set()
        for w in workers:
            w.join(timeout=5)
        try:
            os.remove(PID_FILE)
        except FileNotFoundError:
            pass
        total = sum(w.total_emitted for w in workers)
        print(f"[replay] Stopped. Total docs emitted: {total}", flush=True)
        sys.exit(0)


def stop_replay() -> None:
    """Read the PID file and send SIGTERM to the replay process."""
    try:
        with open(PID_FILE) as fh:
            pid = int(fh.read().strip())
    except FileNotFoundError:
        print(f"[replay] PID file {PID_FILE} not found. Is replay running?")
        sys.exit(1)
    except ValueError:
        print(f"[replay] PID file {PID_FILE} contains invalid content.")
        sys.exit(1)

    try:
        os.kill(pid, signal.SIGTERM)
        print(f"[replay] Sent SIGTERM to PID {pid}.")
    except ProcessLookupError:
        print(f"[replay] Process {pid} not found. Removing stale PID file.")
        try:
            os.remove(PID_FILE)
        except FileNotFoundError:
            pass
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="replay",
        description="Live-tail attack telemetry emitter for the workshop.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # start
    start_p = sub.add_parser("start", help="Start the replay emitter.")
    start_p.add_argument(
        "--host",
        default=None,
        help="Elasticsearch host URL (overrides ES_HOST env var).",
    )
    start_p.add_argument(
        "--api-key",
        default=None,
        dest="api_key",
        help="Elasticsearch API key (overrides ES_API_KEY env var).",
    )
    start_p.add_argument(
        "--bulk-host",
        default=None,
        dest="bulk_host",
        help="Optional bulk ingest endpoint (overrides ES_HOST_BULK env var).",
    )

    # stop
    sub.add_parser("stop", help="Stop a running replay emitter.")

    return parser


def main(argv=None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "stop":
        stop_replay()
        return

    # start: resolve credentials
    env = {}
    try:
        env = load_env()
    except EnvironmentError:
        pass  # we may have explicit --host / --api-key flags

    host = args.host or env.get("ES_HOST")
    api_key = args.api_key or env.get("ES_API_KEY")
    bulk_host = args.bulk_host or env.get("ES_HOST_BULK") or None

    missing = []
    if not host:
        missing.append("--host / ES_HOST")
    if not api_key:
        missing.append("--api-key / ES_API_KEY")
    if missing:
        print(f"[replay] Missing required credentials: {', '.join(missing)}", file=sys.stderr)
        sys.exit(1)

    start_replay(host, api_key, bulk_host)


if __name__ == "__main__":
    main()
