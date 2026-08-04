"""
esclient.py — Elastic connectivity helpers for the agent-intrusion-lab.

Handles environment loading, client construction, readiness checks,
version probing, and Kibana HTTP requests.
"""

from __future__ import annotations

import os
import re
import time
import warnings
from pathlib import Path
from typing import Any, Dict, Optional

import requests
from elasticsearch import Elasticsearch


# ---------------------------------------------------------------------------
# Environment loading
# ---------------------------------------------------------------------------

def _read_dotenv(path: Path) -> Dict[str, str]:
    """Parse a .env file into a dict without external deps."""
    result: Dict[str, str] = {}
    if not path.exists():
        return result
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        # Strip inline comments and surrounding quotes from value
        value = value.strip()
        # Remove inline comment (unquoted)
        if value and value[0] not in ('"', "'"):
            value = value.split("#")[0].strip()
        else:
            # Quoted value — strip the outer quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
        result[key] = value
    return result


def load_env() -> Dict[str, str]:
    """
    Load ES_HOST, ES_HOST_BULK, KIBANA_URL, ES_API_KEY.

    Strategy:
      1. Read .env from the parent of this file's directory.
      2. Prefer actual environment variables over .env values.
      3. Derive KIBANA_URL from ES_HOST if not set.
      4. Raise with a clear message if ES_HOST or ES_API_KEY are missing.

    Returns a dict with all resolved keys.
    """
    env_file = Path(__file__).resolve().parent.parent / ".env"
    file_vals = _read_dotenv(env_file)

    def _get(key: str) -> Optional[str]:
        # Environment wins over .env file
        return os.environ.get(key) or file_vals.get(key) or None

    es_host = _get("ES_HOST")
    es_api_key = _get("ES_API_KEY")
    es_host_bulk = _get("ES_HOST_BULK")
    kibana_url = _get("KIBANA_URL")

    missing = []
    if not es_host:
        missing.append("ES_HOST")
    if not es_api_key:
        missing.append("ES_API_KEY")
    if missing:
        raise EnvironmentError(
            f"Required environment variable(s) not found: {', '.join(missing)}. "
            f"Set them in your environment or in {env_file}."
        )

    # Derive KIBANA_URL if not provided
    if not kibana_url:
        # Replace first occurrence of .es. with .kb. in the hostname portion
        derived = re.sub(r"\.es\.", ".kb.", es_host, count=1)
        if derived == es_host:
            # Fallback: common pattern — swap subdomain prefix
            derived = es_host
        kibana_url = derived
        print(
            f"[esclient] WARNING: KIBANA_URL not set. Derived from ES_HOST: {kibana_url}"
        )

    return {
        "ES_HOST": es_host,
        "ES_API_KEY": es_api_key,
        "ES_HOST_BULK": es_host_bulk or "",
        "KIBANA_URL": kibana_url,
    }


# ---------------------------------------------------------------------------
# Serverless vs ECH detection
# ---------------------------------------------------------------------------

def is_serverless(host: str) -> bool:
    """
    Return True when the host looks like an Elastic Cloud Serverless endpoint.

    Heuristic: hostname contains "elastic.cloud" and no explicit port is present
    in the URL (Serverless endpoints are always HTTPS on 443).
    """
    # Strip scheme
    bare = re.sub(r"^https?://", "", host)
    # Check for explicit port
    has_port = bool(re.search(r":\d+", bare.split("/")[0]))
    return "elastic.cloud" in bare and not has_port


# ---------------------------------------------------------------------------
# Client construction
# ---------------------------------------------------------------------------

def make_es_client(
    host: str,
    api_key: str,
    bulk_host: Optional[str] = None,
) -> Elasticsearch:
    """
    Build an Elasticsearch client with ApiKey auth.

    Parameters
    ----------
    host:
        Primary ES endpoint URL.
    api_key:
        Raw API key string (base64-encoded id:secret or just the secret).
    bulk_host:
        If provided, use this host for the client (ECH ingest endpoint).
    """
    effective_host = bulk_host if bulk_host else host
    client = Elasticsearch(
        effective_host,
        api_key=api_key,
        ssl_show_warn=False,
        verify_certs=True,
        request_timeout=30,
    )
    return client


# ---------------------------------------------------------------------------
# Version probe
# ---------------------------------------------------------------------------

def get_es_version(es_client: Elasticsearch) -> str:
    """Return the version.number string from GET /."""
    info = es_client.info()
    return info["version"]["number"]


def _parse_version(version_str: str):
    """Return a tuple of ints for semver comparison."""
    parts = re.split(r"[.\-]", version_str)
    result = []
    for p in parts[:3]:
        try:
            result.append(int(p))
        except ValueError:
            result.append(0)
    while len(result) < 3:
        result.append(0)
    return tuple(result)


def assert_stack_version(es_client: Elasticsearch, min_version: str = "9.3.0") -> str:
    """
    Raise RuntimeError if stack version is below min_version.

    Required for LLM correlation rules (>= 9.3.0).
    Returns the current version string on success.
    """
    current = get_es_version(es_client)
    if _parse_version(current) < _parse_version(min_version):
        raise RuntimeError(
            f"Stack version {current} is below the required minimum {min_version}. "
            "LLM correlation rules require Elastic Stack >= 9.3.0."
        )
    return current


# ---------------------------------------------------------------------------
# Readiness loop
# ---------------------------------------------------------------------------

def wait_for_ready(
    es_client: Elasticsearch,
    kibana_url: str,
    api_key: str,
    retries: int = 60,
    interval: int = 5,
) -> None:
    """
    Poll ES /_cluster/health and Kibana /api/status until both are reachable.

    Raises RuntimeError after `retries` failed attempts.
    """
    auth_header = {"Authorization": f"ApiKey {api_key}"}
    kibana_status_url = kibana_url.rstrip("/") + "/api/status"

    for attempt in range(1, retries + 1):
        es_ok = False
        kibana_ok = False

        # --- Elasticsearch health check ---
        try:
            health = es_client.cluster.health(request_timeout=10)
            status = health.get("status", "")
            if status in ("green", "yellow"):
                es_ok = True
            else:
                print(
                    f"[esclient] [{attempt}/{retries}] ES cluster status: {status!r} — waiting..."
                )
        except Exception as exc:
            print(f"[esclient] [{attempt}/{retries}] ES not reachable: {exc}")

        # --- Kibana status check ---
        try:
            resp = requests.get(
                kibana_status_url,
                headers=auth_header,
                timeout=10,
                verify=True,
            )
            if resp.status_code == 200:
                payload = resp.json()
                overall = (
                    payload.get("status", {})
                    .get("overall", {})
                    .get("level", "")
                )
                if overall in ("available", "degraded", ""):
                    kibana_ok = True
                else:
                    print(
                        f"[esclient] [{attempt}/{retries}] Kibana status level: {overall!r} — waiting..."
                    )
            else:
                print(
                    f"[esclient] [{attempt}/{retries}] Kibana HTTP {resp.status_code} — waiting..."
                )
        except Exception as exc:
            print(f"[esclient] [{attempt}/{retries}] Kibana not reachable: {exc}")

        if es_ok and kibana_ok:
            print(f"[esclient] Both ES and Kibana are ready (attempt {attempt}).")
            return

        if attempt < retries:
            time.sleep(interval)

    raise RuntimeError(
        f"ES and/or Kibana did not become ready after {retries} attempts "
        f"({retries * interval}s total)."
    )


# ---------------------------------------------------------------------------
# Kibana HTTP helper
# ---------------------------------------------------------------------------

def kibana_request(
    method: str,
    path: str,
    api_key: str,
    kibana_url: str,
    json_body: Optional[Any] = None,
    public: bool = True,
    unversioned: bool = False,
    timeout: int = 30,
) -> Any:
    """
    Make an authenticated HTTP request to Kibana.

    Parameters
    ----------
    method:
        HTTP verb (GET, POST, PUT, DELETE, PATCH).
    path:
        API path, e.g. "/api/detection_engine/rules".
    api_key:
        Raw API key string.
    kibana_url:
        Base URL of Kibana, e.g. "https://my.kb.elastic.cloud".
    json_body:
        Optional request body (will be JSON-serialised).
    public:
        If True, use public API headers (elastic-api-version: 2023-10-31).
        If False, use internal API headers (elastic-api-version: 1 + internal origin).
    unversioned:
        If True, omit all version headers (for alerting backfill endpoints).
        Takes precedence over `public`.

    Returns
    -------
    Parsed JSON response body (dict or list), or None for 204 responses.

    Raises
    ------
    requests.HTTPError on non-2xx responses (after retries).
    """
    url = kibana_url.rstrip("/") + "/" + path.lstrip("/")
    headers: Dict[str, str] = {
        "Authorization": f"ApiKey {api_key}",
        "kbn-xsrf": "true",
    }

    if unversioned:
        # No version header — used for alerting backfill and similar endpoints
        pass
    elif public:
        headers["elastic-api-version"] = "2023-10-31"
    else:
        # Internal Kibana API
        headers["x-elastic-internal-origin"] = "kibana"
        headers["elastic-api-version"] = "1"

    if json_body is not None:
        headers["Content-Type"] = "application/json"

    max_retries = 3
    backoff = 2.0

    last_exc: Optional[Exception] = None
    for attempt in range(max_retries):
        try:
            resp = requests.request(
                method.upper(),
                url,
                headers=headers,
                json=json_body,
                timeout=timeout,
                verify=True,
            )
        except requests.ConnectionError as exc:
            last_exc = exc
            wait = backoff ** attempt
            print(
                f"[esclient] Kibana connection error on {method} {path} "
                f"(attempt {attempt + 1}/{max_retries}): {exc}. Retrying in {wait}s..."
            )
            time.sleep(wait)
            continue

        if resp.status_code in (429, 503):
            wait = backoff ** attempt
            print(
                f"[esclient] Kibana {resp.status_code} on {method} {path} "
                f"(attempt {attempt + 1}/{max_retries}). Retrying in {wait}s..."
            )
            time.sleep(wait)
            last_exc = None  # Will retry
            continue

        # Any other non-2xx → raise with readable message
        if not resp.ok:
            try:
                body_text = resp.text[:2000]
            except Exception:
                body_text = "<unreadable>"
            raise requests.HTTPError(
                f"Kibana {method} {path} returned HTTP {resp.status_code}:\n{body_text}",
                response=resp,
            )

        # Success
        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # Exhausted retries
    if last_exc is not None:
        raise requests.ConnectionError(
            f"Kibana {method} {path} failed after {max_retries} attempts: {last_exc}"
        ) from last_exc
    raise requests.HTTPError(
        f"Kibana {method} {path} returned 429/503 after {max_retries} attempts."
    )


# ---------------------------------------------------------------------------
# Convenience wrappers used by rules.py / backfill.py / verify.py
# ---------------------------------------------------------------------------

def kibana_get(
    path: str,
    api_key: str,
    kibana_url: str,
    params: Optional[Dict[str, Any]] = None,
    public: bool = True,
    unversioned: bool = False,
    timeout: int = 30,
) -> Any:
    """GET a Kibana path, appending query params if supplied."""
    if params:
        from urllib.parse import urlencode
        path = f"{path}?{urlencode(params)}"
    return kibana_request(
        "GET", path, api_key=api_key, kibana_url=kibana_url,
        public=public, unversioned=unversioned, timeout=timeout,
    )


def kibana_post(
    path: str,
    body: Any,
    api_key: str,
    kibana_url: str,
    public: bool = True,
    unversioned: bool = False,
    timeout: int = 30,
) -> Any:
    """POST a JSON body to a Kibana path."""
    return kibana_request(
        "POST", path, api_key=api_key, kibana_url=kibana_url,
        json_body=body, public=public, unversioned=unversioned, timeout=timeout,
    )
