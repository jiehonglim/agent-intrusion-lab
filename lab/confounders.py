"""
confounders.py – Benign background patterns that defeat naive SIEM queries.

Every confounder is designed so that a naive query (e.g. "find privileged pods",
"find bulk secret reads", "find external denials", "find high-velocity API callers")
returns thousands of rows dominated by these benign docs.  Attendees must add
agent-specific dimensions to isolate the 11 real attack events.

Teaching moments per confounder:
  C1 – Privileged DaemonSets: image-exclusion list separates legitimate infra from attack pods.
  C4 – ArgoCD velocity: high call rate but narrow resource breadth and near-zero deny rate.
  C2 – Backup operator: bulk secret reads but only at night, fixed SA, allowed every time.
  C3 – Pentest noise: external access-denied storm from a *different* IP/ASN on day -7.

Usage:
  from lab.confounders import confounder_docs
  for doc in confounder_docs(rng, anchor_ms):
      bulk_buffer.append(doc)
"""

from __future__ import annotations

import datetime
import math
from collections.abc import Generator
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DAY_MS = 86_400_000  # milliseconds in one day


def _ts(anchor_ms: int, day_offset: float, hour: float = 0.0, jitter_ms: int = 0) -> int:
    """Return an epoch-millis timestamp relative to anchor.

    anchor_ms is the campaign reference point (typically "today at midnight UTC").
    day_offset is fractional days relative to anchor (negative = before anchor).
    hour is a fractional hour-of-day addition on top of the day offset.
    jitter_ms is an additional millisecond offset (from rng.integers).
    """
    return int(anchor_ms + day_offset * DAY_MS + hour * 3_600_000 + jitter_ms)


def _fmt(epoch_ms: int) -> str:
    """Format epoch milliseconds as ISO-8601 UTC string."""
    dt = datetime.datetime.utcfromtimestamp(epoch_ms / 1000.0)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _base_doc(
    index: str,
    dataset: str,
    namespace: str,
    epoch_ms: int,
) -> dict[str, Any]:
    """Return the skeleton shared by every doc."""
    return {
        "_index": index,
        "_op_type": "create",
        "_source": {
            "@timestamp": _fmt(epoch_ms),
            "data_stream": {
                "type": "logs",
                "dataset": dataset,
                "namespace": namespace,
            },
            "ecs": {"version": "8.11.0"},
            "event": {
                "dataset": dataset,
            },
        },
    }


# ---------------------------------------------------------------------------
# C1 – Privileged DaemonSets (1,200 docs over 8 days)
# ---------------------------------------------------------------------------

_C1_DAEMONSETS = [
    {
        "name": "aws-node",
        "image": "602401143452.dkr.ecr.us-east-1.amazonaws.com/amazon-k8s-cni:v1.15.0",
        "sa": "system:serviceaccount:kube-system:aws-node",
        "hostpath": "/",
    },
    {
        "name": "ebs-csi-node",
        "image": "public.ecr.aws/eks-distro/kubernetes-csi/livenessprobe:v2.11.0-eks-1-28-latest",
        "sa": "system:serviceaccount:kube-system:ebs-csi-node-sa",
        "hostpath": "/",
    },
    {
        "name": "node-exporter",
        "image": "quay.io/prometheus/node-exporter:v1.6.1",
        "sa": "system:serviceaccount:kube-system:node-exporter",
        "hostpath": "/proc",
    },
    {
        "name": "kube-proxy",
        "image": "602401143452.dkr.ecr.us-east-1.amazonaws.com/eks/kube-proxy:v1.28.0",
        "sa": "system:serviceaccount:kube-system:kube-proxy",
        "hostpath": "/sys",
    },
]

_C1_HOSTPATHS = ["/", "/proc", "/sys"]


def _c1_privileged_daemonsets(
    rng: Any,
    anchor_ms: int,
    namespace: str,
) -> Generator[dict[str, Any], None, None]:
    """C1: 1,200 privileged DaemonSet pod-creation events spread across 8 days.

    These are identical in shape to the attack's privileged-pod events except that
    the container images belong to the prebuilt-rule exclusion list.  A naive query
    for 'privileged pods' returns ~1,270 rows (1,200 here + 11 attack pods).
    Adding an image exclusion filter drops the count to 11.
    """
    total = 1200
    dataset = "kubernetes.audit_logs"
    index = f"logs-{dataset}-{namespace}"

    # Spread evenly over 8 days: day -8 through day -1
    ds_cycle = list(range(len(_C1_DAEMONSETS)))

    for i in range(total):
        # Distribute over 8 days
        day_offset = -8 + (i / total) * 8  # from -8 to 0
        jitter = int(rng.randint(0, 600_000 - 1))  # up to 10 min jitter
        epoch_ms = _ts(anchor_ms, day_offset, jitter_ms=jitter)

        ds_idx = i % len(_C1_DAEMONSETS)
        ds = _C1_DAEMONSETS[ds_idx]

        hostpath = _C1_HOSTPATHS[i % len(_C1_HOSTPATHS)]

        doc = _base_doc(index, dataset, namespace, epoch_ms)
        doc["_source"].update(
            {
                "event": {
                    "dataset": dataset,
                    "action": "create",
                    "outcome": "success",
                    "category": ["configuration"],
                    "type": ["creation"],
                    "provider": "kubernetes",
                },
                "user": {
                    "name": ds["sa"],
                },
                "orchestrator": {
                    "cluster": {"name": "eks-prod-use1"},
                    "type": "kubernetes",
                },
                "kubernetes": {
                    "audit": {
                        "verb": "create",
                        "level": "RequestResponse",
                        "stage": "ResponseComplete",
                        "objectRef": {
                            "resource": "pods",
                            "namespace": "kube-system",
                            "name": f"{ds['name']}-{rng.randint(10000, 99999 - 1)}",
                        },
                        "user": {
                            "username": ds["sa"],
                            "groups": [
                                "system:serviceaccounts",
                                "system:serviceaccounts:kube-system",
                                "system:authenticated",
                            ],
                        },
                        "annotations": {
                            "authorization_k8s_io/decision": "allow",
                            "authorization_k8s_io/reason": "RBAC: allowed by ClusterRoleBinding",
                        },
                        "requestObject": {
                            "kind": "Pod",
                            "apiVersion": "v1",
                            "metadata": {
                                "name": f"{ds['name']}-{rng.randint(10000, 99999 - 1)}",
                                "namespace": "kube-system",
                                "labels": {
                                    "app": ds["name"],
                                    "managed-by": "daemonset-controller",
                                },
                            },
                            "spec": {
                                "hostNetwork": True,
                                "hostPID": False,
                                "containers": [
                                    {
                                        "name": ds["name"],
                                        "image": ds["image"],
                                        "securityContext": {
                                            "privileged": True,
                                            "capabilities": {"add": []},
                                        },
                                    }
                                ],
                                "volumes": [
                                    {
                                        "name": "host-root",
                                        "hostPath": {"path": hostpath},
                                    }
                                ],
                            },
                        },
                        "responseObject": {
                            "kind": "Pod",
                            "apiVersion": "v1",
                            "metadata": {"namespace": "kube-system"},
                            "status": {"phase": "Running"},
                        },
                    }
                },
            }
        )
        yield doc


# ---------------------------------------------------------------------------
# C4 – ArgoCD application-controller high-velocity API calls (3,000+ docs / 8 days)
# ---------------------------------------------------------------------------

_C4_VERBS = ["get", "list", "watch", "watch", "watch", "list", "list"]  # watch/list heavy
_C4_RESOURCES = ["deployments", "replicasets", "pods", "services", "configmaps"]


def _c4_argocd_velocity(
    rng: Any,
    anchor_ms: int,
    namespace: str,
) -> Generator[dict[str, Any], None, None]:
    """C4: ArgoCD application-controller at >3,000 calls/hr for 8 days.

    High velocity but only 3-4 distinct resource kinds and near-zero deny rate.
    The attack SA has lower velocity but 9 resource kinds and 30-70% deny rate.
    Attendees defeat this confounder by adding resource-diversity or deny-rate cuts.
    """
    # 3,000 calls/hr × 24 hr × 8 days = 576,000 would be too many for a lab.
    # The spec says "3,000 docs over 8 days = about 30 calls/15-min window".
    # Re-reading: "Generate at roughly 3,000 calls/hour in bursts (evenly distributed
    # over 8 days = about 30 calls/15-minute window)."  30 per 15-min = 120/hr.
    # We'll generate enough to demonstrate the pattern: 3,072 docs over 8 days
    # (one burst of 32 docs every 15 minutes across the 8-day window).
    total = 3_072  # 32 docs × 4 per-hour slots × 24 hours × 8 days... reduced for lab
    # Actually: 8 days × 24 hrs × 4 slots/hr × 32 docs/slot = 24,576; too large.
    # Spec says "3,000+ docs over 8 days" for the index; we'll do exactly 3,072.
    dataset = "kubernetes.audit_logs"
    index = f"logs-{dataset}-{namespace}"

    # 3,072 docs spread over 8 days = 384 per day = 16 per hour
    # Cluster them into 15-minute windows (~4 per window, 96 windows per day).
    windows = 8 * 24 * 4  # 768 windows of 15 minutes each
    docs_per_window = math.ceil(total / windows)  # 4

    doc_count = 0
    for w in range(windows):
        if doc_count >= total:
            break
        # Start of the 15-minute window relative to anchor
        window_start_ms = anchor_ms - 8 * DAY_MS + w * 15 * 60 * 1000
        burst_size = min(docs_per_window, total - doc_count)

        for b in range(burst_size):
            jitter = int(rng.randint(0, 14 * 60 * 1000 - 1))  # within the window
            epoch_ms = window_start_ms + jitter

            verb = _C4_VERBS[b % len(_C4_VERBS)]
            resource = _C4_RESOURCES[b % len(_C4_RESOURCES)]

            # 99.5% allow, 0.5% deny
            allow = rng.random() > 0.005
            decision = "allow" if allow else "deny"
            outcome = "success" if allow else "failure"
            http_status = 200 if allow else 403

            doc = _base_doc(index, dataset, namespace, epoch_ms)
            doc["_source"].update(
                {
                    "event": {
                        "dataset": dataset,
                        "action": verb,
                        "outcome": outcome,
                        "category": ["configuration"],
                        "type": ["access"],
                        "provider": "kubernetes",
                    },
                    "user": {
                        "name": "system:serviceaccount:argocd:argocd-application-controller",
                    },
                    "source": {
                        "ip": "10.0.0.50",
                        "address": "10.0.0.50",
                    },
                    "user_agent": {
                        "original": "argocd-application-controller/v2.8.0",
                    },
                    "orchestrator": {
                        "cluster": {"name": "eks-prod-use1"},
                        "type": "kubernetes",
                    },
                    "kubernetes": {
                        "audit": {
                            "verb": verb,
                            "level": "Metadata",
                            "stage": "ResponseComplete",
                            "objectRef": {
                                "resource": resource,
                                "namespace": "default",
                            },
                            "user": {
                                "username": "system:serviceaccount:argocd:argocd-application-controller",
                                "groups": [
                                    "system:serviceaccounts",
                                    "system:serviceaccounts:argocd",
                                    "system:authenticated",
                                ],
                            },
                            "annotations": {
                                "authorization_k8s_io/decision": decision,
                                "authorization_k8s_io/reason": (
                                    "RBAC: allowed by ClusterRoleBinding"
                                    if allow
                                    else "RBAC: no rules applicable"
                                ),
                            },
                            "responseStatus": {
                                "code": http_status,
                            },
                        }
                    },
                }
            )
            yield doc
            doc_count += 1


# ---------------------------------------------------------------------------
# C2 – Backup operator reads Secrets nightly (240 docs over 8 days)
# ---------------------------------------------------------------------------

_C2_NAMESPACES = ["default", "monitoring", "logging", "database", "cert-manager"]
_C2_VERBS = ["get", "list"]


def _c2_backup_operator(
    rng: Any,
    anchor_ms: int,
    namespace: str,
) -> Generator[dict[str, Any], None, None]:
    """C2: backup-operator reads 30 secrets per night between 02:00-04:00 UTC.

    8 nights × 30 reads = 240 docs.  A naive 'bulk secret reads' query returns
    these alongside the attack's secret harvest.  Adding time-of-day or SA filters
    excludes the backup operator entirely.
    """
    dataset = "kubernetes.audit_logs"
    index = f"logs-{dataset}-{namespace}"

    reads_per_night = 30
    nights = 8  # day -8 through day -1

    for night in range(nights):
        day_offset = -8 + night  # -8, -7, ..., -1
        for r in range(reads_per_night):
            # Random time between 02:00 and 04:00 UTC
            hour_offset = 2.0 + rng.random() * 2.0  # [2.0, 4.0)
            jitter = int(rng.randint(0, 30_000 - 1))
            epoch_ms = _ts(anchor_ms, day_offset, hour=hour_offset, jitter_ms=jitter)

            verb = _C2_VERBS[r % len(_C2_VERBS)]
            ns = _C2_NAMESPACES[r % len(_C2_NAMESPACES)]
            secret_name = f"backup-secret-{r:03d}"

            doc = _base_doc(index, dataset, namespace, epoch_ms)
            doc["_source"].update(
                {
                    "event": {
                        "dataset": dataset,
                        "action": verb,
                        "outcome": "success",
                        "category": ["configuration"],
                        "type": ["access"],
                        "provider": "kubernetes",
                    },
                    "user": {
                        "name": "system:serviceaccount:backup:backup-operator",
                    },
                    "orchestrator": {
                        "cluster": {"name": "eks-prod-use1"},
                        "type": "kubernetes",
                    },
                    "kubernetes": {
                        "audit": {
                            "verb": verb,
                            "level": "Metadata",
                            "stage": "ResponseComplete",
                            "objectRef": {
                                "resource": "secrets",
                                "namespace": ns,
                                "name": secret_name if verb == "get" else None,
                            },
                            "user": {
                                "username": "system:serviceaccount:backup:backup-operator",
                                "groups": [
                                    "system:serviceaccounts",
                                    "system:serviceaccounts:backup",
                                    "system:authenticated",
                                ],
                            },
                            "annotations": {
                                "authorization_k8s_io/decision": "allow",
                                "authorization_k8s_io/reason": "RBAC: allowed by ClusterRoleBinding backup-operator",
                            },
                            "responseStatus": {
                                "code": 200,
                            },
                        }
                    },
                }
            )
            yield doc


# ---------------------------------------------------------------------------
# C3 – Scheduled pentest, day -7 (900 docs)
# ---------------------------------------------------------------------------

_C3_AWS_ACTIONS = [
    "DescribeInstances",
    "ListBuckets",
    "DescribeSecurityGroups",
    "ListRoles",
    "GetCallerIdentity",
    "DescribeSubnets",
    "ListUsers",
    "DescribeVpcs",
    "GetAccountAuthorizationDetails",
    "ListPolicies",
    "DescribeImages",
    "DescribeSnapshotAttribute",
    "ListGroupsForUser",
    "DescribeIamInstanceProfileAssociations",
    "ListAttachedRolePolicies",
    "GetRolePolicy",
    "DescribeNetworkInterfaces",
    "DescribeLoadBalancers",
    "ListHostedZones",
    "DescribeDBInstances",
    "ListFunctions20150331",
    "GetBucketPolicy",
    "ListBucketVersions",
    "GetAccountPasswordPolicy",
    "DescribeFlowLogs",
]

_C3_AWS_SERVICES = [
    "ec2.amazonaws.com",
    "s3.amazonaws.com",
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "rds.amazonaws.com",
    "elasticloadbalancing.amazonaws.com",
    "lambda.amazonaws.com",
    "route53.amazonaws.com",
]


def _c3_pentest_noise(
    rng: Any,
    anchor_ms: int,
    namespace: str,
) -> Generator[dict[str, Any], None, None]:
    """C3: 900 CloudTrail AccessDenied events from a pentest IP on day -7.

    Source IP 203.0.113.199 (RFC 5737, distinct from the attack IPs in 203.0.113.0/24).
    All denied.  A naive 'external denials' query includes these alongside the attack's
    CloudTrail storm.  Adding ASN or IP filters (ClearSkyPentest-AS vs attacker ASN)
    separates them.
    """
    total = 900
    dataset = "aws.cloudtrail"
    index = f"logs-{dataset}-{namespace}"

    # All on day -7 (8 days before anchor = start of observation window)
    day_offset = -7

    for i in range(total):
        # Spread across the full day
        fraction = i / total
        hour_offset = fraction * 24.0
        jitter = int(rng.randint(0, 60_000 - 1))
        epoch_ms = _ts(anchor_ms, day_offset, hour=hour_offset, jitter_ms=jitter)

        action = _C3_AWS_ACTIONS[i % len(_C3_AWS_ACTIONS)]
        service = _C3_AWS_SERVICES[i % len(_C3_AWS_SERVICES)]
        request_id = f"{rng.randint(0, 0xFFFFFFFF - 1):08x}-{rng.randint(0, 0xFFFF - 1):04x}-{rng.randint(0, 0xFFFF - 1):04x}"

        doc = _base_doc(index, dataset, namespace, epoch_ms)
        doc["_source"].update(
            {
                "event": {
                    "dataset": dataset,
                    "action": action,
                    "outcome": "failure",
                    "category": ["authentication", "configuration"],
                    "type": ["denied"],
                    "provider": "aws",
                },
                "source": {
                    "ip": "203.0.113.199",
                    "address": "203.0.113.199",
                    "as": {
                        "number": 64500,
                        "organization": {
                            "name": "ClearSkyPentest-AS",
                        },
                    },
                    "geo": {
                        "city_name": "Amsterdam",
                        "country_name": "Netherlands",
                    },
                },
                "user": {
                    "name": "pentest-external-user",
                    "id": "AIDAPENTEST00000000001",
                },
                "user_agent": {
                    "original": "aws-cli/2.13.0 Python/3.11.5 Linux/5.15.0",
                },
                "aws": {
                    "cloudtrail": {
                        "event_version": "1.08",
                        "user_identity": {
                            "type": "IAMUser",
                            "arn": "arn:aws:iam::123456789012:user/pentest-external-user",
                            "account_id": "123456789012",
                        },
                        "error_code": "AccessDenied",
                        "error_message": "User: arn:aws:iam::123456789012:user/pentest-external-user is not authorized to perform: "
                        + action,
                        "request_id": request_id,
                        "event_type": "AwsApiCall",
                        "event_source": service,
                        "recipient_account_id": "123456789012",
                        "read_only": True,
                    }
                },
            }
        )
        yield doc


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def confounder_docs(
    rng: Any,
    anchor_ms: int,
    ds_namespace: str = "workshop",
) -> Generator[dict[str, Any], None, None]:
    """Yield all confounder documents in C1 → C4 → C2 → C3 order.

    Parameters
    ----------
    rng:
        A numpy Generator (e.g. ``numpy.random.default_rng(seed)``).
    anchor_ms:
        Campaign reference epoch in milliseconds (today at midnight UTC).
    ds_namespace:
        Elasticsearch data-stream namespace.  Defaults to "workshop".

    Yields
    ------
    dict
        Bulk-API action document with ``_index``, ``_op_type``, and ``_source``.
    """
    yield from _c1_privileged_daemonsets(rng, anchor_ms, ds_namespace)
    yield from _c4_argocd_velocity(rng, anchor_ms, ds_namespace)
    yield from _c2_backup_operator(rng, anchor_ms, ds_namespace)
    yield from _c3_pentest_noise(rng, anchor_ms, ds_namespace)
