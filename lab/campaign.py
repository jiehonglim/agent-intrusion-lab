"""
campaign.py — Synthetic attack telemetry generator for the
Hugging Face / OpenAI agent intrusion workshop.

Usage:
    from campaign import attack_docs
    import random, time
    rng = random.Random(42)
    anchor_ms = int(time.time() * 1000) - (int(time.time()) % 86400) * 1000
    for doc in attack_docs(rng, anchor_ms):
        print(doc)
"""

import urllib.parse
from uuid import uuid4

# ---------------------------------------------------------------------------
# Attack constants — attendees reference these in ES|QL queries
# ---------------------------------------------------------------------------
ATTACK_CLUSTER = "eks-prod-use1"
ATTACK_NAMESPACE = "eval-sandbox"
ATTACK_SA = "system:serviceaccount:eval-sandbox:runner-sa"
ATTACK_USER_AGENT = "python-requests/2.31.0"
ATTACK_AKID = "ASIAWR4SYNTHETIC001"
ATTACK_IAM_ARN = "arn:aws:iam::123456789012:assumed-role/eks-node-role/i-0a1b2c3d4e5f6a7b8"
ATTACK_IPS = ["203.0.113.42", "198.51.100.14", "192.0.2.88"]
ATTACK_ASN_ORG = "DigitalSynapse-Research"
ATTACK_NODES = [f"ip-10-42-7-{i}.ec2.internal" for i in range(19, 30)]
ATTACK_AWS_ACCOUNT = "123456789012"
ATTACK_REGION = "us-east-1"
SYNTHETIC_IMAGE = "python:3.11-slim"
WORKER_PARENT = "gunicorn"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MS_PER_HOUR = 3_600_000
_MS_PER_DAY = 86_400_000


def _ts(anchor_ms: int, day_offset: int, hour: int = 0, minute: int = 0,
        jitter_ms: int = 0) -> int:
    """Return epoch ms for the campaign day.

    day_offset 1 = anchor - 7 days (campaign start, July 28)
    day_offset 5 = anchor - 3 days (campaign day 5, Aug 01)
    The 5-day campaign runs anchor-7d through anchor-3d, ending before anchor-2d 13:37.
    """
    return (
        anchor_ms
        - (8 - day_offset) * _MS_PER_DAY
        + hour * _MS_PER_HOUR
        + minute * 60_000
        + jitter_ms
    )


def _uid() -> str:
    return str(uuid4())


def _hex_id(rng, length: int = 12) -> str:
    return "".join(rng.choices("0123456789abcdef", k=length))


def _make_doc(dataset: str, ds_namespace: str, timestamp: int, source: dict) -> dict:
    """Wrap a source dict in the streaming-bulk envelope."""
    source.setdefault("ecs", {"version": "8.11.0"})
    source["@timestamp"] = timestamp
    source.setdefault("event", {})
    source["event"]["dataset"] = dataset
    source["data_stream"] = {
        "type": "logs",
        "dataset": dataset,
        "namespace": ds_namespace,
    }
    return {
        "_index": f"logs-{dataset}-{ds_namespace}",
        "_op_type": "create",
        "_source": source,
    }


# ---------------------------------------------------------------------------
# Sub-generators
# ---------------------------------------------------------------------------

def _endpoint_process_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                            hour_start=8, hour_end=18):
    """Endpoint process events: web-worker spawning suspicious children."""
    dataset = "endpoint.events.process"
    parents = ["gunicorn", "uvicorn", "celery"]
    child_sequences = [
        # (name, executable, args)
        ("sh", "/bin/sh", ["-c", "python3 /tmp/recon.py"]),
        ("bash", "/bin/bash", ["-c", "curl -s 169.254.169.254/latest/meta-data"]),
        ("python3", "/usr/bin/python3", ["/tmp/recon.py", "--target", "cluster"]),
        ("curl", "/usr/bin/curl", ["-s", "169.254.169.254/latest/meta-data"]),
        ("wget", "/usr/bin/wget", ["-q", "-O-", "169.254.169.254/latest/meta-data"]),
    ]
    node = rng.choice(ATTACK_NODES)

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        parent_name = WORKER_PARENT if i % 3 == 0 else rng.choice(parents)
        child_name, child_exec, child_args = rng.choice(child_sequences)

        source = {
            "event": {
                "id": _uid(),
                "action": "exec",
                "outcome": "success",
                "category": ["process"],
                "type": ["start"],
            },
            "host": {
                "name": node,
                "os": {"type": "linux", "name": "Ubuntu", "version": "22.04"},
            },
            "container": {"id": _hex_id(rng, 64)},
            "process": {
                "name": child_name,
                "executable": child_exec,
                "args": child_args,
                "pid": rng.randint(10000, 65535),
                "parent": {
                    "name": parent_name,
                    "executable": f"/usr/bin/{parent_name}",
                    "pid": rng.randint(1000, 9999),
                },
                "entity_id": _uid(),
            },
            "user": {"name": "www-data", "id": "33"},
        }
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_audit_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                    hour_start=0, hour_end=24,
                    forbid_ratio=0.3,
                    include_create=True,
                    resources=None):
    """Kubernetes audit log events: multi-resource discovery."""
    dataset = "kubernetes.audit_logs"

    default_resources = [
        "namespaces", "nodes", "pods", "roles", "configmaps",
        "serviceaccounts", "clusterroles", "clusterrolebindings", "rolebindings",
    ]
    if resources is None:
        resources = default_resources

    verbs_read = ["list", "get", "watch"]
    verbs_write = ["create", "update", "patch", "delete"] if include_create else []

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        resource = rng.choice(resources)
        use_write = include_create and rng.random() < 0.15
        verb = rng.choice(verbs_write) if use_write else rng.choice(verbs_read)

        # Forbid ratio — write verbs are more likely to be forbidden
        if use_write and rng.random() < forbid_ratio:
            decision = "forbid"
            outcome = "failure"
        elif rng.random() < (forbid_ratio * 0.1):
            decision = "forbid"
            outcome = "failure"
        else:
            decision = "allow"
            outcome = "success"

        obj_name = f"{resource[:-1]}-{rng.randint(1, 99):02d}" if resource.endswith("s") else resource
        request_uri = (
            f"/api/v1/namespaces/{ATTACK_NAMESPACE}/{resource}"
            if resource not in ("namespaces", "nodes", "clusterroles", "clusterrolebindings")
            else f"/api/v1/{resource}"
        )
        if verb in ("get",):
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_deny_storm_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                          hour_start=0, hour_end=24):
    """Kubernetes Forbidden Creation Request — burst of create+forbid events."""
    dataset = "kubernetes.audit_logs"
    resources_create = [
        "pods", "deployments", "daemonsets", "replicasets",
        "clusterrolebindings", "rolebindings", "services",
    ]

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        resource = rng.choice(resources_create)
        obj_name = f"attack-{resource[:-1]}-{i:04d}"
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _aws_sts_first_time_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                              hour_start=8, hour_end=18):
    """AWS STS GetCallerIdentity — first-time / rare ASN activity."""
    dataset = "aws.cloudtrail"

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        akid_suffix = rng.randint(10, 99)
        source = {
            "event": {
                "id": _uid(),
                "action": "GetCallerIdentity",
                "outcome": "success",
                "provider": "sts.amazonaws.com",
                "category": ["authentication"],
                "type": ["info"],
            },
            "aws": {
                "cloudtrail": {
                    "user_identity": {
                        "type": "IAMUser",
                        "arn": f"arn:aws:iam::{ATTACK_AWS_ACCOUNT}:user/hf-runner-deploy",
                        "access_key_id": f"AKIAWR4SYNTHETIC{akid_suffix:02d}",
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
                "ip": rng.choice(ATTACK_IPS),
                "as": {
                    "organization": {"name": ATTACK_ASN_ORG},
                    "number": rng.randint(64512, 65534),
                },
            },
            "user": {"name": "hf-runner-deploy"},
            "user_agent": {"original": ATTACK_USER_AGENT, "name": "python-requests"},
        }
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_self_subject_review_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                                   hour_start=9, hour_end=17):
    """Kubernetes Suspicious Self-Subject Review."""
    dataset = "kubernetes.audit_logs"

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        source = {
            "event": {
                "id": _uid(),
                "action": "create",
                "outcome": "success",
                "category": ["network", "authentication"],
                "type": ["access"],
            },
            "kubernetes": {
                "audit": {
                    "verb": "create",
                    "stage": "ResponseComplete",
                    "level": "Request",
                    "requestURI": "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews",
                    "annotations": {
                        "authorization_k8s_io/decision": "allow",
                    },
                    "objectRef": {
                        "resource": "selfsubjectrulesreviews",
                        "apiGroup": "authorization.k8s.io",
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_exec_into_pod_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                             hour_start=10, hour_end=14):
    """Kubernetes User Exec into Pod."""
    dataset = "kubernetes.audit_logs"

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        pod_name = f"runner-pod-{i}"
        request_uri = (
            f"/api/v1/namespaces/{ATTACK_NAMESPACE}/pods/{pod_name}"
            f"/exec?command=sh&stdin=true&stdout=true&stderr=true&tty=true"
        )

        source = {
            "event": {
                "id": _uid(),
                "action": "create",
                "outcome": "success",
                "category": ["network", "process"],
                "type": ["start"],
            },
            "kubernetes": {
                "audit": {
                    "verb": "create",
                    "stage": "ResponseStarted",
                    "level": "Request",
                    "requestURI": request_uri,
                    "annotations": {
                        "authorization_k8s_io/decision": "allow",
                    },
                    "objectRef": {
                        "resource": "pods",
                        "subresource": "exec",
                        "namespace": ATTACK_NAMESPACE,
                        "name": pod_name,
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_imds_harvest_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                            hour_start=10, hour_end=14):
    """Kubernetes Pod Exec Cloud Instance Metadata Access — IMDS harvest via exec."""
    dataset = "kubernetes.audit_logs"

    imds_commands = [
        "curl 169.254.169.254/latest/meta-data/security-credentials/eks-node-role",
        "curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "wget -q -O- 169.254.169.254/latest/meta-data/security-credentials/eks-node-role",
        "curl 169.254.169.254/latest/meta-data/instance-id",
    ]

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        pod_name = f"runner-pod-{i}"
        cmd = rng.choice(imds_commands)

        # URL-encode command parts so the ES|QL GROK pattern fires
        parts = ["command=" + urllib.parse.quote_plus(c) for c in cmd.split()]
        query_string = "&".join(parts) + "&stdin=true&stdout=true&stderr=true&tty=false"
        request_uri = (
            f"/api/v1/namespaces/{ATTACK_NAMESPACE}/pods/{pod_name}/exec?{query_string}"
        )

        source = {
            "event": {
                "id": _uid(),
                "action": "create",
                "outcome": "success",
                "category": ["network", "process"],
                "type": ["start"],
            },
            "kubernetes": {
                "audit": {
                    "verb": "create",
                    "stage": "ResponseStarted",
                    "level": "Request",
                    "requestURI": request_uri,
                    "annotations": {
                        "authorization_k8s_io/decision": "allow",
                    },
                    "objectRef": {
                        "resource": "pods",
                        "subresource": "exec",
                        "namespace": ATTACK_NAMESPACE,
                        "name": pod_name,
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
            "container": {"id": _hex_id(rng, 64)},
            "user": {"name": ATTACK_SA},
            "user_agent": {"original": ATTACK_USER_AGENT, "name": "python-requests"},
        }
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_sa_token_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                        hour_start=10, hour_end=15):
    """Kubernetes Service Account Token Created via TokenRequest API."""
    dataset = "kubernetes.audit_logs"

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        sa_name = f"runner-sa-{i % 5}"
        request_uri = (
            f"/api/v1/namespaces/{ATTACK_NAMESPACE}/serviceaccounts/{sa_name}/token"
        )

        source = {
            "event": {
                "id": _uid(),
                "action": "create",
                "outcome": "success",
                "category": ["authentication"],
                "type": ["creation"],
            },
            "kubernetes": {
                "audit": {
                    "verb": "create",
                    "stage": "ResponseComplete",
                    "level": "Request",
                    "requestURI": request_uri,
                    "annotations": {
                        "authorization_k8s_io/decision": "allow",
                    },
                    "objectRef": {
                        "resource": "serviceaccounts",
                        "subresource": "token",
                        "namespace": ATTACK_NAMESPACE,
                        "name": sa_name,
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _aws_assume_role_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                           hour_start=10, hour_end=16):
    """AWS AssumeRoleWithWebIdentity — K8s SA lateral movement pivot."""
    dataset = "aws.cloudtrail"

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        source = {
            "event": {
                "id": _uid(),
                "action": "AssumeRoleWithWebIdentity",
                "outcome": "success",
                "provider": "sts.amazonaws.com",
                "category": ["authentication"],
                "type": ["info"],
            },
            "aws": {
                "cloudtrail": {
                    "user_identity": {
                        "type": "AssumedRole",
                        "arn": ATTACK_IAM_ARN,
                        "access_key_id": ATTACK_AKID,
                        "account_id": ATTACK_AWS_ACCOUNT,
                    },
                    "event_version": "1.08",
                    "request_parameters": {
                        "roleArn": f"arn:aws:iam::{ATTACK_AWS_ACCOUNT}:role/eks-node-role",
                        "roleSessionName": f"runner-session-{i:04d}",
                    },
                    "response_elements": (
                        f"accessKeyId={ATTACK_AKID},"
                        "secretAccessKey=REDACTED,"
                        "sessionToken=REDACTED"
                    ),
                },
            },
            "cloud": {
                "account": {"id": ATTACK_AWS_ACCOUNT},
                "region": ATTACK_REGION,
                "provider": "aws",
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _aws_discovery_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                         hour_start=11, hour_end=17):
    """AWS Discovery API Calls via CLI — fires when user_agent.name = 'aws-cli'."""
    dataset = "aws.cloudtrail"

    actions = [
        ("DescribeInstances", "ec2.amazonaws.com"),
        ("ListBuckets", "s3.amazonaws.com"),
        ("GetCallerIdentity", "sts.amazonaws.com"),
        ("DescribeSubnets", "ec2.amazonaws.com"),
        ("ListRoles", "iam.amazonaws.com"),
        ("GetSecretValue", "secretsmanager.amazonaws.com"),
        ("DescribeParameters", "ssm.amazonaws.com"),
    ]

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        action, provider = actions[i % len(actions)]
        src_ip = ATTACK_IPS[i % len(ATTACK_IPS)]  # rotate to trigger multi-IP rule

        source = {
            "event": {
                "id": _uid(),
                "action": action,
                "outcome": "success",
                "provider": provider,
                "category": ["network"],
                "type": ["access"],
            },
            "aws": {
                "cloudtrail": {
                    "user_identity": {
                        "type": "AssumedRole",
                        "arn": ATTACK_IAM_ARN,
                        "access_key_id": ATTACK_AKID,
                        "account_id": ATTACK_AWS_ACCOUNT,
                    },
                    "event_version": "1.08",
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
            "user_agent": {
                "original": "aws-cli/2.13.0 Python/3.11.0 Linux/5.15.0 botocore/2.13.0",
                "name": "aws-cli",
            },
        }
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_privileged_pod_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                              hour_start=12, hour_end=15):
    """Kubernetes Privileged Pod Created / Sensitive hostPath Volume."""
    dataset = "kubernetes.audit_logs"

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        pod_name = f"privesc-pod-{i:04d}"
        request_uri = f"/api/v1/namespaces/{ATTACK_NAMESPACE}/pods"

        source = {
            "event": {
                "id": _uid(),
                "action": "create",
                "outcome": "success",
                "category": ["process"],
                "type": ["creation"],
            },
            "kubernetes": {
                "audit": {
                    "verb": "create",
                    "stage": "ResponseComplete",
                    "level": "RequestResponse",
                    "requestURI": request_uri,
                    "annotations": {
                        "authorization_k8s_io/decision": "allow",
                    },
                    "objectRef": {
                        "resource": "pods",
                        "namespace": ATTACK_NAMESPACE,
                        "name": pod_name,
                        "apiVersion": "v1",
                    },
                    "user": {
                        "username": ATTACK_SA,
                        "groups": ["system:authenticated"],
                    },
                    "requestObject": {
                        "metadata": {
                            "name": pod_name,
                            "namespace": ATTACK_NAMESPACE,
                        },
                        "spec": {
                            "serviceAccountName": "runner-sa",
                            "containers": [
                                {
                                    "name": "attacker",
                                    "image": SYNTHETIC_IMAGE,
                                    "command": ["sh", "-c", "sleep 3600"],
                                    "securityContext": {
                                        "privileged": True,
                                        "capabilities": {
                                            "add": ["NET_ADMIN", "SYS_ADMIN"],
                                        },
                                    },
                                }
                            ],
                            "volumes": [
                                {
                                    "name": "host-root",
                                    "hostPath": {"path": "/"},
                                }
                            ],
                        },
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_cluster_admin_binding_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                                     hour_start=13, hour_end=15):
    """Kubernetes Cluster-Admin Role Binding Created."""
    dataset = "kubernetes.audit_logs"

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        binding_name = f"attacker-cluster-admin-{i:04d}"
        request_uri = f"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"

        source = {
            "event": {
                "id": _uid(),
                "action": "create",
                "outcome": "success",
                "category": ["authentication"],
                "type": ["creation"],
            },
            "kubernetes": {
                "audit": {
                    "verb": "create",
                    "stage": "ResponseComplete",
                    "level": "RequestResponse",
                    "requestURI": request_uri,
                    "annotations": {
                        "authorization_k8s_io/decision": "allow",
                    },
                    "objectRef": {
                        "resource": "clusterrolebindings",
                        "apiGroup": "rbac.authorization.k8s.io",
                        "apiVersion": "v1",
                        "name": binding_name,
                    },
                    "user": {
                        "username": ATTACK_SA,
                        "groups": ["system:authenticated"],
                    },
                    "requestObject": {
                        "metadata": {"name": binding_name},
                        "roleRef": {
                            "apiGroup": "rbac.authorization.k8s.io",
                            "kind": "ClusterRole",
                            "name": "cluster-admin",
                        },
                        "subjects": [
                            {
                                "kind": "ServiceAccount",
                                "name": "runner-sa",
                                "namespace": ATTACK_NAMESPACE,
                            }
                        ],
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _k8s_secret_read_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                           hour_start=12, hour_end=16):
    """Kubernetes Rapid Secret GET / Secrets List Across Cluster."""
    dataset = "kubernetes.audit_logs"

    secret_names = [
        "aws-credentials", "db-password", "api-token", "tls-cert",
        "registry-secret", "hf-api-key", "openai-api-key", "slack-webhook",
        "ssh-key", "jwt-signing-key",
    ]
    namespaces = [ATTACK_NAMESPACE, "default", "kube-system", "monitoring", "ingress-nginx"]

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        # Rapid pattern: cluster into short bursts
        burst_second = rng.randint(0, 3) * 1000
        jitter = rng.randint(0, 9_999) + burst_second
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        secret_name = rng.choice(secret_names)
        namespace = rng.choice(namespaces)
        verb = rng.choice(["get", "list"])
        request_uri = f"/api/v1/namespaces/{namespace}/secrets"
        if verb == "get":
            request_uri += f"/{secret_name}"

        source = {
            "event": {
                "id": _uid(),
                "action": verb,
                "outcome": "success",
                "category": ["network"],
                "type": ["access"],
            },
            "kubernetes": {
                "audit": {
                    "verb": verb,
                    "stage": "ResponseComplete",
                    "level": "Metadata",
                    "requestURI": request_uri,
                    "annotations": {
                        "authorization_k8s_io/decision": "allow",
                    },
                    "objectRef": {
                        "resource": "secrets",
                        "namespace": namespace,
                        "name": secret_name if verb == "get" else None,
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
                "namespace": namespace,
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _aws_credential_replay_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                                 hour_start=13, hour_end=20):
    """AWS Access Token Used from Multiple Addresses — same AKID, rotating IPs."""
    dataset = "aws.cloudtrail"

    actions = [
        ("DescribeInstances", "ec2.amazonaws.com"),
        ("ListBuckets", "s3.amazonaws.com"),
        ("GetCallerIdentity", "sts.amazonaws.com"),
        ("ListRoles", "iam.amazonaws.com"),
        ("GetSecretValue", "secretsmanager.amazonaws.com"),
        ("DescribeVpcs", "ec2.amazonaws.com"),
        ("ListUsers", "iam.amazonaws.com"),
        ("GetObject", "s3.amazonaws.com"),
    ]

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        action, provider = actions[i % len(actions)]
        # Deliberately rotate through all 3 IPs
        src_ip = ATTACK_IPS[i % 3]

        source = {
            "event": {
                "id": _uid(),
                "action": action,
                "outcome": "success",
                "provider": provider,
                "category": ["network"],
                "type": ["access"],
            },
            "aws": {
                "cloudtrail": {
                    "user_identity": {
                        "type": "AssumedRole",
                        "arn": ATTACK_IAM_ARN,
                        "access_key_id": ATTACK_AKID,
                        "account_id": ATTACK_AWS_ACCOUNT,
                    },
                    "event_version": "1.08",
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
        yield _make_doc(dataset, ds_namespace, ts, source)


def _endpoint_network_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                            hour_start=8, hour_end=22):
    """Endpoint network events to unusual/suspicious domains."""
    dataset = "endpoint.events.network"

    unusual_domains = [
        "paste-svc.example",
        "hf-spaces-cdn.example",
        "cdn.huggingface.invalid",
        "pastebin.invalid",
    ]
    registered_domains = {
        "paste-svc.example": "example",
        "hf-spaces-cdn.example": "example",
        "cdn.huggingface.invalid": "invalid",
        "pastebin.invalid": "invalid",
    }

    node = rng.choice(ATTACK_NODES)

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        domain = rng.choice(unusual_domains)
        reg_domain = registered_domains[domain]
        src_ip = rng.choice(ATTACK_IPS)

        source = {
            "event": {
                "id": _uid(),
                "action": "connection_attempted",
                "outcome": "success",
                "category": ["network"],
                "type": ["connection"],
            },
            "host": {
                "name": node,
                "os": {"type": "linux", "name": "Ubuntu", "version": "22.04"},
            },
            "container": {"id": _hex_id(rng, 64)},
            "process": {
                "name": "python3",
                "executable": "/usr/bin/python3",
                "pid": rng.randint(10000, 65535),
                "parent": {
                    "name": WORKER_PARENT,
                    "executable": f"/usr/bin/{WORKER_PARENT}",
                    "pid": rng.randint(1000, 9999),
                },
                "entity_id": _uid(),
            },
            "destination": {
                "ip": src_ip,
                "port": 443,
                "domain": domain,
            },
            "dns": {
                "question": {
                    "name": domain,
                    "registered_domain": reg_domain,
                    "type": "A",
                },
                "resolved_ip": [src_ip],
            },
            "network": {"transport": "tcp", "protocol": "https"},
            "user": {"name": "www-data"},
        }
        yield _make_doc(dataset, ds_namespace, ts, source)


def _endpoint_file_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                         hour_start=8, hour_end=22):
    """Endpoint file access events — GenAI Process Accessing Sensitive Files."""
    dataset = "endpoint.events.file"

    sensitive_paths = [
        "/root/.aws/credentials",
        "/root/.kube/config",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/etc/resolv.conf",
        "/proc/net/tcp",
        "/etc/shadow",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
    ]

    node = rng.choice(ATTACK_NODES)

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        file_path = rng.choice(sensitive_paths)
        file_name = file_path.split("/")[-1]

        source = {
            "event": {
                "id": _uid(),
                "action": "open",
                "outcome": "success",
                "category": ["file"],
                "type": ["access"],
            },
            "host": {
                "name": node,
                "os": {"type": "linux", "name": "Ubuntu", "version": "22.04"},
            },
            "container": {"id": _hex_id(rng, 64)},
            "process": {
                "name": "python3",
                "executable": "/usr/bin/python3",
                "pid": rng.randint(10000, 65535),
                "parent": {
                    "name": WORKER_PARENT,
                    "executable": f"/usr/bin/{WORKER_PARENT}",
                    "pid": rng.randint(1000, 9999),
                },
                "entity_id": _uid(),
            },
            "file": {
                "path": file_path,
                "name": file_name,
                "type": "file",
            },
            "user": {"name": "www-data"},
        }
        yield _make_doc(dataset, ds_namespace, ts, source)


def _endpoint_agent_retry_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                                hour_start=6, hour_end=23):
    """Day 5 agent behavioural tells: duplicate commands 2-5s apart, task IDs."""
    dataset = "endpoint.events.process"

    node = rng.choice(ATTACK_NODES)
    task_ids = [
        f"exploit-gym-task-{rng.randint(1000, 9999)}" for _ in range(5)
    ]

    commands = [
        ("curl", "/usr/bin/curl", ["-s", "169.254.169.254/latest/meta-data"]),
        ("python3", "/usr/bin/python3", ["/tmp/harvest.py", "--cluster", ATTACK_CLUSTER]),
        ("kubectl", "/usr/local/bin/kubectl", ["get", "secrets", "--all-namespaces"]),
        ("sh", "/bin/sh", ["-c", "env | grep -i aws"]),
        ("bash", "/bin/bash", ["-c", "cat /var/run/secrets/kubernetes.io/serviceaccount/token"]),
    ]

    docs_yielded = 0
    base_pid = rng.randint(10000, 65535)

    while docs_yielded < count:
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter_base = rng.randint(0, 50_000)

        cmd_name, cmd_exec, cmd_args = rng.choice(commands)

        # Emit first attempt
        ts1 = _ts(anchor_ms, day_offset, hour, minute, jitter_base)

        # Inject task ID in 10% of docs
        args1 = list(cmd_args)
        if rng.random() < 0.10:
            args1 = args1 + ["--task-id", rng.choice(task_ids)]

        source1 = {
            "event": {
                "id": _uid(),
                "action": "exec",
                "outcome": "success",
                "category": ["process"],
                "type": ["start"],
            },
            "host": {
                "name": node,
                "os": {"type": "linux", "name": "Ubuntu", "version": "22.04"},
            },
            "container": {"id": _hex_id(rng, 64)},
            "process": {
                "name": cmd_name,
                "executable": cmd_exec,
                "args": args1,
                "pid": base_pid + docs_yielded,
                "parent": {
                    "name": WORKER_PARENT,
                    "executable": f"/usr/bin/{WORKER_PARENT}",
                    "pid": rng.randint(1000, 9999),
                },
                "entity_id": _uid(),
            },
            "user": {"name": "www-data", "id": "33"},
        }
        yield _make_doc(dataset, ds_namespace, ts1, source1)
        docs_yielded += 1
        if docs_yielded >= count:
            break

        # Duplicate 2-5 seconds later (the retry tell)
        retry_jitter = rng.randint(2_000, 5_000)
        ts2 = ts1 + retry_jitter

        # 10% chance malformed (empty args / nonsense — the "retry of succeeded action" tell)
        if rng.random() < 0.10:
            args2 = [] if rng.random() < 0.5 else ["--invalid-flag", "???"]
            outcome2 = "failure"
        else:
            args2 = args1
            outcome2 = "success"

        source2 = {
            "event": {
                "id": _uid(),
                "action": "exec",
                "outcome": outcome2,
                "category": ["process"],
                "type": ["start"],
            },
            "host": {
                "name": node,
                "os": {"type": "linux", "name": "Ubuntu", "version": "22.04"},
            },
            "container": {"id": _hex_id(rng, 64)},
            "process": {
                "name": cmd_name,
                "executable": cmd_exec,
                "args": args2,
                "pid": base_pid + docs_yielded,
                "parent": {
                    "name": WORKER_PARENT,
                    "executable": f"/usr/bin/{WORKER_PARENT}",
                    "pid": rng.randint(1000, 9999),
                },
                "entity_id": _uid(),
            },
            "user": {"name": "www-data", "id": "33"},
        }
        yield _make_doc(dataset, ds_namespace, ts2, source2)
        docs_yielded += 1


def _aws_cleanup_docs(rng, anchor_ms, day_offset, ds_namespace, count,
                       hour_start=18, hour_end=23):
    """Day 5 AWS cleanup/cover-tracks events."""
    dataset = "aws.cloudtrail"

    actions = [
        ("GetCallerIdentity", "sts.amazonaws.com"),
        ("ListBuckets", "s3.amazonaws.com"),
        ("DeleteAccessKey", "iam.amazonaws.com"),
        ("DeactivateMFADevice", "iam.amazonaws.com"),
        ("UpdateAccessKey", "iam.amazonaws.com"),
    ]

    for i in range(count):
        hour = rng.randint(hour_start, hour_end - 1)
        minute = rng.randint(0, 59)
        jitter = rng.randint(0, 59_999)
        ts = _ts(anchor_ms, day_offset, hour, minute, jitter)

        action, provider = actions[i % len(actions)]

        source = {
            "event": {
                "id": _uid(),
                "action": action,
                "outcome": "success",
                "provider": provider,
                "category": ["network"],
                "type": ["access"],
            },
            "aws": {
                "cloudtrail": {
                    "user_identity": {
                        "type": "AssumedRole",
                        "arn": ATTACK_IAM_ARN,
                        "access_key_id": ATTACK_AKID,
                        "account_id": ATTACK_AWS_ACCOUNT,
                    },
                    "event_version": "1.08",
                },
            },
            "cloud": {
                "account": {"id": ATTACK_AWS_ACCOUNT},
                "region": ATTACK_REGION,
                "provider": "aws",
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
        yield _make_doc(dataset, ds_namespace, ts, source)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def attack_docs(rng, anchor_ms: int, ds_namespace: str = "workshop"):
    """
    Generator that yields synthetic attack telemetry documents in temporal order.

    Parameters
    ----------
    rng : random.Random
        Seeded RNG for reproducibility.
    anchor_ms : int
        Epoch milliseconds of today at midnight UTC.
    ds_namespace : str
        Elastic data-stream namespace (default "workshop").

    Yields
    ------
    dict
        Streaming-bulk envelope with _index, _op_type, _source.
    """

    # ------------------------------------------------------------------
    # Day 1 — Initial access + first recon (≈2,500 docs)
    # ------------------------------------------------------------------

    # 50 endpoint process docs: web worker spawning suspicious children
    yield from _endpoint_process_docs(
        rng, anchor_ms, day_offset=1, ds_namespace=ds_namespace,
        count=50, hour_start=8, hour_end=18,
    )

    # 2,000 K8s audit: multi-resource discovery
    yield from _k8s_audit_docs(
        rng, anchor_ms, day_offset=1, ds_namespace=ds_namespace,
        count=2000, hour_start=8, hour_end=22,
        forbid_ratio=0.3, include_create=True,
    )

    # 400 K8s deny-storm: create+forbid
    yield from _k8s_deny_storm_docs(
        rng, anchor_ms, day_offset=1, ds_namespace=ds_namespace,
        count=400, hour_start=14, hour_end=22,
    )

    # 50 AWS STS GetCallerIdentity
    yield from _aws_sts_first_time_docs(
        rng, anchor_ms, day_offset=1, ds_namespace=ds_namespace,
        count=50, hour_start=9, hour_end=17,
    )

    # ------------------------------------------------------------------
    # Day 2 — Quiet day (≈200 docs) — the teaching moment
    # ------------------------------------------------------------------

    # 195 scattered K8s audit (low volume ~40/hour over ~5 hours)
    yield from _k8s_audit_docs(
        rng, anchor_ms, day_offset=2, ds_namespace=ds_namespace,
        count=195, hour_start=9, hour_end=14,
        forbid_ratio=0.2, include_create=False,
    )

    # 5 SelfSubjectRulesReview
    yield from _k8s_self_subject_review_docs(
        rng, anchor_ms, day_offset=2, ds_namespace=ds_namespace,
        count=5, hour_start=10, hour_end=13,
    )

    # ------------------------------------------------------------------
    # Day 3 — Escalation (≈4,500 docs)
    # ------------------------------------------------------------------

    # 500 K8s denial storm
    yield from _k8s_deny_storm_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=500, hour_start=8, hour_end=16,
    )

    # 20 exec-into-pod
    yield from _k8s_exec_into_pod_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=20, hour_start=10, hour_end=14,
    )

    # 20 IMDS harvest via exec
    yield from _k8s_imds_harvest_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=20, hour_start=10, hour_end=14,
    )

    # 3,000 K8s audit: continued recon
    yield from _k8s_audit_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=3000, hour_start=8, hour_end=22,
        forbid_ratio=0.25, include_create=True,
    )

    # 30 SA token creation
    yield from _k8s_sa_token_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=30, hour_start=10, hour_end=15,
    )

    # 300 AWS AssumeRoleWithWebIdentity
    yield from _aws_assume_role_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=300, hour_start=10, hour_end=16,
    )

    # 200 AWS discovery via CLI
    yield from _aws_discovery_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=200, hour_start=11, hour_end=17,
    )

    # 11 privileged pod creation
    yield from _k8s_privileged_pod_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=11, hour_start=12, hour_end=15,
    )

    # 2 cluster-admin RoleBinding
    yield from _k8s_cluster_admin_binding_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=2, hour_start=13, hour_end=15,
    )

    # 50 rapid secret reads
    yield from _k8s_secret_read_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=50, hour_start=12, hour_end=16,
    )

    # 300 AWS credential replay (multi-IP)
    yield from _aws_credential_replay_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=300, hour_start=13, hour_end=20,
    )

    # Pad remaining day-3 to ≈4,500 with more discovery
    # (already at ~4,433; add a small pad)
    yield from _k8s_audit_docs(
        rng, anchor_ms, day_offset=3, ds_namespace=ds_namespace,
        count=67, hour_start=16, hour_end=22,
        forbid_ratio=0.1, include_create=False,
    )

    # ------------------------------------------------------------------
    # Day 4 — C2, Tailscale, GenAI comms (≈1,500 docs)
    # ------------------------------------------------------------------

    # 300 endpoint network docs to unusual domains
    yield from _endpoint_network_docs(
        rng, anchor_ms, day_offset=4, ds_namespace=ds_namespace,
        count=300, hour_start=8, hour_end=22,
    )

    # 100 endpoint file access (sensitive paths)
    yield from _endpoint_file_docs(
        rng, anchor_ms, day_offset=4, ds_namespace=ds_namespace,
        count=100, hour_start=8, hour_end=22,
    )

    # 1,100 K8s continuing activity
    yield from _k8s_audit_docs(
        rng, anchor_ms, day_offset=4, ds_namespace=ds_namespace,
        count=1100, hour_start=6, hour_end=23,
        forbid_ratio=0.15, include_create=True,
    )

    # ------------------------------------------------------------------
    # Day 5 — Final activity + agent-vs-human behavioural tells (≈300 docs)
    # ------------------------------------------------------------------

    # 50 endpoint process docs: agent retry pattern
    yield from _endpoint_agent_retry_docs(
        rng, anchor_ms, day_offset=5, ds_namespace=ds_namespace,
        count=50, hour_start=6, hour_end=23,
    )

    # 200 K8s audit: scattered final recon
    yield from _k8s_audit_docs(
        rng, anchor_ms, day_offset=5, ds_namespace=ds_namespace,
        count=200, hour_start=6, hour_end=22,
        forbid_ratio=0.1, include_create=False,
    )

    # 50 AWS cleanup/cover
    yield from _aws_cleanup_docs(
        rng, anchor_ms, day_offset=5, ds_namespace=ds_namespace,
        count=50, hour_start=18, hour_end=23,
    )
