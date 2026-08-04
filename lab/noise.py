"""
noise.py – ambient background traffic generator
Fills the corpus to ~330,000 total documents with realistic but boring ops data.
No diurnal curve, no weekend dips – weekday-agnostic flat distribution.
"""

from __future__ import annotations

import random
import uuid
from typing import Generator

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WINDOW_MS = 8 * 24 * 60 * 60 * 1000  # 8-day window in milliseconds

# Proportions must sum to 1.0
K8S_FRAC = 0.60
CLOUD_FRAC = 0.25
PROC_FRAC = 0.10
NET_FRAC = 0.05

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts(rng: random.Random, anchor_ms: int, window_ms: int = WINDOW_MS) -> str:
    """Random ISO-8601 timestamp within [anchor_ms, anchor_ms + window_ms)."""
    offset = rng.randint(0, window_ms - 1)
    ms = anchor_ms + offset
    s, remainder = divmod(ms, 1000)
    from datetime import datetime, timezone
    dt = datetime.fromtimestamp(s, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{remainder:03d}Z"


def _uid() -> str:
    return str(uuid.uuid4())


def _internal_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


# ---------------------------------------------------------------------------
# K8s audit ambient (~60%)
# ---------------------------------------------------------------------------

_K8S_SERVICE_ACCOUNTS = [
    "system:serviceaccount:kube-system:kube-proxy",
    "system:serviceaccount:monitoring:prometheus",
    "system:serviceaccount:default:default",
    "system:serviceaccount:kube-system:coredns",
    "system:serviceaccount:kube-system:node-problem-detector",
]

# Each SA only touches ≤3 resource kinds
_SA_RESOURCES: dict[str, list[tuple[str, str]]] = {
    "system:serviceaccount:kube-system:kube-proxy": [
        ("get", "nodes"),
        ("list", "nodes"),
        ("watch", "nodes"),
    ],
    "system:serviceaccount:monitoring:prometheus": [
        ("get", "pods"),
        ("list", "pods"),
        ("list", "services"),
    ],
    "system:serviceaccount:default:default": [
        ("get", "namespaces"),
        ("list", "namespaces"),
        ("get", "configmaps"),
    ],
    "system:serviceaccount:kube-system:coredns": [
        ("list", "endpoints"),
        ("watch", "endpoints"),
        ("get", "services"),
    ],
    "system:serviceaccount:kube-system:node-problem-detector": [
        ("get", "nodes"),
        ("list", "events"),
        ("get", "pods"),
    ],
}

_K8S_NAMESPACES = ["default", "kube-system", "monitoring", "production", "staging"]


def _k8s_doc(rng: random.Random, anchor_ms: int, ds_namespace: str) -> dict:
    sa = rng.choice(_K8S_SERVICE_ACCOUNTS)
    verb, resource = rng.choice(_SA_RESOURCES[sa])
    ns = rng.choice(_K8S_NAMESPACES)
    src_ip = _internal_ip(rng)
    timestamp = _ts(rng, anchor_ms)

    return {
        "_index": f".ds-logs-kubernetes.audit_logs-{ds_namespace}-000001",
        "_op_type": "create",
        "_source": {
            "@timestamp": timestamp,
            "data_stream": {
                "type": "logs",
                "dataset": "kubernetes.audit_logs",
                "namespace": ds_namespace,
            },
            "event": {
                "action": verb,
                "outcome": "allow",
                "category": ["authentication"],
                "type": ["info"],
            },
            "kubernetes": {
                "audit": {
                    "verb": verb,
                    "objectRef": {
                        "resource": resource,
                        "namespace": ns,
                    },
                    "user": {
                        "username": sa,
                        "groups": ["system:serviceaccounts", "system:authenticated"],
                    },
                    "sourceIPs": [src_ip],
                    "requestURI": f"/api/v1/namespaces/{ns}/{resource}",
                    "responseStatus": {"code": 200},
                    "stage": "ResponseComplete",
                }
            },
            "source": {
                "ip": src_ip,
                "as": {"organization": {"name": None}},
            },
            "orchestrator": {
                "cluster": {"name": "eks-prod-use1"},
                "type": "kubernetes",
            },
            "user": {"name": sa},
            "event_id": _uid(),
        },
    }


# ---------------------------------------------------------------------------
# AWS CloudTrail ambient (~25%)
# ---------------------------------------------------------------------------

_CLOUD_PROVIDERS = [
    ("ec2.amazonaws.com", ["DescribeInstances", "DescribeSecurityGroups", "DescribeSubnets"]),
    ("rds.amazonaws.com", ["DescribeDBInstances", "DescribeDBClusters", "ListTagsForResource"]),
    ("s3.amazonaws.com", ["PutObject", "GetObject", "ListBucket", "HeadObject"]),
    ("sts.amazonaws.com", ["AssumeRole", "GetCallerIdentity"]),
    ("elasticloadbalancing.amazonaws.com", ["DescribeLoadBalancers", "DescribeTargetGroups"]),
]

_CLOUD_SOURCE_IPS = [
    "10.0.1.50",
    "10.0.2.75",
    "10.1.0.100",
    "52.94.133.131",
    "54.239.28.85",
]

_CLOUD_ORG_NAMES = ["AMAZON-02", "Amazon Technologies Inc.", None]

_CLOUD_ROLES = [
    "arn:aws:iam::123456789012:role/eks-node-role",
    "arn:aws:iam::123456789012:role/lambda-exec-role",
    "arn:aws:iam::123456789012:role/rds-monitoring-role",
    "arn:aws:iam::123456789012:role/s3-backup-role",
    "arn:aws:iam::123456789012:role/ci-deploy-role",
]

_CLOUD_REGIONS = ["us-east-1", "us-west-2", "eu-west-1"]


def _cloud_doc(rng: random.Random, anchor_ms: int, ds_namespace: str) -> dict:
    provider, actions = rng.choice(_CLOUD_PROVIDERS)
    action = rng.choice(actions)
    src_ip = rng.choice(_CLOUD_SOURCE_IPS)
    org = rng.choice(_CLOUD_ORG_NAMES)
    role = rng.choice(_CLOUD_ROLES)
    region = rng.choice(_CLOUD_REGIONS)
    timestamp = _ts(rng, anchor_ms)

    return {
        "_index": f".ds-logs-aws.cloudtrail-{ds_namespace}-000001",
        "_op_type": "create",
        "_source": {
            "@timestamp": timestamp,
            "data_stream": {
                "type": "logs",
                "dataset": "aws.cloudtrail",
                "namespace": ds_namespace,
            },
            "event": {
                "action": action,
                "provider": provider,
                "outcome": "success",
                "category": ["configuration"],
                "type": ["info"],
            },
            "aws": {
                "cloudtrail": {
                    "event_name": action,
                    "event_source": provider,
                    "aws_region": region,
                    "user_identity": {
                        "type": "AssumedRole",
                        "arn": role,
                        "account_id": "123456789012",
                        "session_context": {
                            "session_issuer": {
                                "type": "Role",
                                "arn": role,
                            }
                        },
                    },
                    "request_id": _uid(),
                }
            },
            "source": {
                "ip": src_ip,
                "as": {"organization": {"name": org}},
            },
            "cloud": {
                "provider": "aws",
                "region": region,
                "account": {"id": "123456789012"},
            },
            "user": {"name": role.split("/")[-1]},
            "event_id": _uid(),
        },
    }


# ---------------------------------------------------------------------------
# Endpoint process ambient (~10%)
# ---------------------------------------------------------------------------

_PROC_PARENTS = ["systemd", "cron", "supervisord", "init", "bash"]
_PROC_NAMES = ["bash", "python3", "curl", "sh", "node", "perl"]
_PROC_ARGS = [
    "/usr/local/bin/health-check.sh",
    "/opt/app/rotate-logs.py",
    "http://localhost:9090/metrics",
    "/etc/cron.daily/backup",
    "/usr/bin/logrotate /etc/logrotate.conf",
]
_PROC_HOSTS = [
    "ip-10-0-1-101.ec2.internal",
    "ip-10-0-2-52.ec2.internal",
    "ip-10-1-0-33.ec2.internal",
    "worker-node-01",
    "worker-node-02",
    "worker-node-03",
]


def _proc_doc(rng: random.Random, anchor_ms: int, ds_namespace: str) -> dict:
    parent = rng.choice(_PROC_PARENTS)
    proc = rng.choice(_PROC_NAMES)
    args = rng.choice(_PROC_ARGS)
    host = rng.choice(_PROC_HOSTS)
    pid = rng.randint(1000, 65000)
    ppid = rng.randint(1, 999)
    timestamp = _ts(rng, anchor_ms)

    return {
        "_index": f".ds-logs-endpoint.events.process-{ds_namespace}-000001",
        "_op_type": "create",
        "_source": {
            "@timestamp": timestamp,
            "data_stream": {
                "type": "logs",
                "dataset": "endpoint.events.process",
                "namespace": ds_namespace,
            },
            "event": {
                "action": "exec",
                "category": ["process"],
                "type": ["start"],
                "outcome": "success",
            },
            "process": {
                "name": proc,
                "executable": f"/usr/bin/{proc}",
                "pid": pid,
                "args": [f"/usr/bin/{proc}", args],
                "parent": {
                    "name": parent,
                    "pid": ppid,
                    "executable": f"/usr/bin/{parent}",
                },
            },
            "host": {
                "name": host,
                "os": {
                    "type": "linux",
                    "name": "Amazon Linux",
                    "version": "2",
                },
                "ip": [_internal_ip(rng)],
            },
            "user": {"name": "root", "id": "0"},
            "event_id": _uid(),
        },
    }


# ---------------------------------------------------------------------------
# Endpoint network ambient (~5%)
# ---------------------------------------------------------------------------

_NET_PROC_NAMES = ["prometheus", "node-exporter", "kube-proxy", "curl", "kubelet"]
_NET_DEST_DOMAINS = [
    "kubernetes.default.svc.cluster.local",
    "kube-dns.kube-system.svc.cluster.local",
    "prometheus.monitoring.svc.cluster.local",
    "grafana.monitoring.svc.cluster.local",
    "metrics-server.kube-system.svc.cluster.local",
]
_NET_DEST_PORTS = [443, 8080, 9090, 9100, 10250, 10255, 53]


def _net_doc(rng: random.Random, anchor_ms: int, ds_namespace: str) -> dict:
    proc = rng.choice(_NET_PROC_NAMES)
    dest_domain = rng.choice(_NET_DEST_DOMAINS)
    dest_port = rng.choice(_NET_DEST_PORTS)
    src_ip = _internal_ip(rng)
    dest_ip = _internal_ip(rng)
    host = rng.choice(_PROC_HOSTS)
    bytes_sent = rng.randint(200, 4096)
    bytes_recv = rng.randint(500, 65536)
    timestamp = _ts(rng, anchor_ms)

    return {
        "_index": f".ds-logs-endpoint.events.network-{ds_namespace}-000001",
        "_op_type": "create",
        "_source": {
            "@timestamp": timestamp,
            "data_stream": {
                "type": "logs",
                "dataset": "endpoint.events.network",
                "namespace": ds_namespace,
            },
            "event": {
                "action": "connection_attempted",
                "category": ["network"],
                "type": ["connection"],
                "outcome": "success",
            },
            "process": {
                "name": proc,
                "executable": f"/usr/bin/{proc}",
                "pid": rng.randint(1000, 65000),
            },
            "source": {
                "ip": src_ip,
                "port": rng.randint(32768, 60999),
            },
            "destination": {
                "ip": dest_ip,
                "port": dest_port,
                "domain": dest_domain,
            },
            "network": {
                "transport": "tcp",
                "direction": "outbound",
                "bytes": bytes_sent + bytes_recv,
            },
            "host": {
                "name": host,
                "os": {"type": "linux"},
                "ip": [src_ip],
            },
            "event_id": _uid(),
        },
    }


# ---------------------------------------------------------------------------
# Public generator
# ---------------------------------------------------------------------------

def noise_docs(
    rng: random.Random,
    anchor_ms: int,
    needed: int,
    ds_namespace: str = "workshop",
) -> Generator[dict, None, None]:
    """
    Yield `needed` ambient noise documents distributed across four categories.

    Parameters
    ----------
    rng         : seeded Random instance for reproducibility
    anchor_ms   : start of the 8-day window in epoch-milliseconds
    needed      : how many docs to generate (0 → yields nothing)
    ds_namespace: Elastic data-stream namespace
    """
    if needed <= 0:
        return

    # Compute per-category counts (floor), assign remainder to k8s
    n_cloud = int(needed * CLOUD_FRAC)
    n_proc = int(needed * PROC_FRAC)
    n_net = int(needed * NET_FRAC)
    n_k8s = needed - n_cloud - n_proc - n_net  # absorbs rounding

    # Build a list of (count, generator_fn) pairs
    buckets: list[tuple[int, object]] = [
        (n_k8s, _k8s_doc),
        (n_cloud, _cloud_doc),
        (n_proc, _proc_doc),
        (n_net, _net_doc),
    ]

    # Interleave by shuffling a slot list so docs aren't all sorted by type
    slots: list[object] = []
    for count, fn in buckets:
        slots.extend([fn] * count)

    rng.shuffle(slots)

    for fn in slots:
        yield fn(rng, anchor_ms, ds_namespace)  # type: ignore[operator]
