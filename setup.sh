#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
export PYTHONPATH="$SCRIPT_DIR:${PYTHONPATH:-}"

# ── Defaults ──────────────────────────────────────────────────────────────────
PROFILE=""
SKIP_RULES=false
NO_REPLAY=false
VERIFY_ONLY=false
STOP_REPLAY=false

# ── Argument parsing ───────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --profile <name>   Load environment from .env.<name>
  --skip-rules       Skip prebuilt rule install + enable (data only)
  --no-replay        Historical + backfill only (no live replay)
  --verify-only      Re-run verification only
  --stop-replay      Kill the live replay process and exit
  --help             Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      PROFILE="$2"
      shift 2
      ;;
    --skip-rules)
      SKIP_RULES=true
      shift
      ;;
    --no-replay)
      NO_REPLAY=true
      shift
      ;;
    --verify-only)
      VERIFY_ONLY=true
      shift
      ;;
    --stop-replay)
      STOP_REPLAY=true
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

# ── Environment loading ────────────────────────────────────────────────────────

# Set up environment variables
echo 'ELASTICSEARCH_USERNAME=elastic' >> "$SCRIPT_DIR/.env"
kubectl get secret elasticsearch-es-elastic-user -n default -o go-template='ELASTICSEARCH_PASSWORD={{.data.elastic | base64decode}}' >> "$SCRIPT_DIR/.env"
echo '' >> /root/.env
echo 'ES_HOST="http://localhost:30920"' >> "$SCRIPT_DIR/.env"
echo 'KIBANA_URL="http://localhost:30002"' >> "$SCRIPT_DIR/.env"

load_env_file() {
  local env_file="$1"
  if [[ -f "$env_file" ]]; then
    echo "Loading environment from $env_file"
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
  fi
}

if [[ -n "$PROFILE" ]]; then
  load_env_file "$SCRIPT_DIR/.env.${PROFILE}"
else
  load_env_file "$SCRIPT_DIR/.env"
fi

# Support Instruqt/k8s environment variable conventions
# ELASTICSEARCH_URL is the Instruqt name for the ES endpoint
ES_HOST="${ES_HOST:-${ELASTICSEARCH_URL:-}}"

# In k8s Instruqt labs the ECK operator stores the elastic password in a secret.
# Pull it automatically when no password has been supplied via .env.
# if [[ -z "${ELASTICSEARCH_PASSWORD:-}" && -z "${ES_PASSWORD:-}" ]] && command -v kubectl &>/dev/null; then
#   _k8s_pass=$(kubectl get secret elasticsearch-es-elastic-user -n default \
#     -o go-template='{{.data.elastic | base64decode}}' 2>/dev/null || true)
#   if [[ -n "$_k8s_pass" ]]; then
#     ELASTICSEARCH_PASSWORD="$_k8s_pass"
#     echo "Loaded ELASTICSEARCH_PASSWORD from k8s secret (elasticsearch-es-elastic-user)"
#   fi
# fi

# # ELASTICSEARCH_USERNAME / ELASTICSEARCH_PASSWORD → ES_USERNAME / ES_PASSWORD
ES_USERNAME="${ES_USERNAME:-${ELASTICSEARCH_USERNAME:-}}"
ES_PASSWORD="${ES_PASSWORD:-${ELASTICSEARCH_PASSWORD:-}}"

# ── Helper: stage timing ───────────────────────────────────────────────────────
STAGE_START=0
stage_begin() {
  echo ""
  echo "=== $1 ==="
  STAGE_START=$(date +%s)
}

stage_end() {
  local end
  end=$(date +%s)
  local elapsed=$(( end - STAGE_START ))
  echo "    Done in ${elapsed}s"
}

# ── Helper: total elapsed ──────────────────────────────────────────────────────
format_elapsed() {
  local total_secs="$1"
  local mins=$(( total_secs / 60 ))
  local secs=$(( total_secs % 60 ))
  if [[ $mins -gt 0 ]]; then
    echo "${mins}m ${secs}s"
  else
    echo "${secs}s"
  fi
}

TOTAL_START=$(date +%s)

# ── Stop replay shortcut ───────────────────────────────────────────────────────
if [[ "$STOP_REPLAY" == true ]]; then
  echo "=== Stopping live replay ==="
  python3 -m lab.replay stop
  echo "Replay stopped."
  exit 0
fi

# ── Verify only shortcut ──────────────────────────────────────────────────────
if [[ "$VERIFY_ONLY" == true ]]; then
  stage_begin "[verify-only] Verify"
  python3 -m lab.verify
  stage_end
  TOTAL_END=$(date +%s)
  echo ""
  echo "=== Verify Complete ==="
  echo "Elapsed: $(format_elapsed $(( TOTAL_END - TOTAL_START )))"
  exit 0
fi

# ═════════════════════════════════════════════════════════════════════════════
# [1/9] Preflight
# ═════════════════════════════════════════════════════════════════════════════
stage_begin "[1/9] Preflight"

# Validate required env vars
if [[ -z "${ES_HOST:-}" ]]; then
  echo "ERROR: ES_HOST is required." >&2
  exit 1
fi

# Auth: accept username+password OR pre-issued API key
# If username+password supplied, generate a scoped API key and use that
# for all subsequent steps (Python modules expect ES_API_KEY).
if [[ -n "${ES_USERNAME:-}" && -n "${ES_PASSWORD:-}" ]]; then
  echo "Auth: username/password → generating API key for session..."
  BASE64=$(echo -n "${ES_USERNAME}:${ES_PASSWORD}" | base64)
  _key_resp=$(curl -sf -m 15 \
    -H "Authorization: Basic ${BASE64}" \
    -H "Content-Type: application/json" \
    "${ES_HOST}/_security/api_key" \
    -d '{"name":"workshop-setup","expiration":"12h","role_descriptors":{}}')
  if [[ -z "$_key_resp" ]]; then
    echo "ERROR: Failed to generate API key from username/password." >&2
    exit 1
  fi
  # encoded field is id:api_key base64 — ready for Authorization: ApiKey header
  ES_API_KEY=$(echo "$_key_resp" | python3 -c "import sys,json; print(json.load(sys.stdin)['encoded'])")
  echo "API key generated OK"
elif [[ -z "${ES_API_KEY:-}" ]]; then
  echo "ERROR: Provide either ES_API_KEY or ES_USERNAME + ES_PASSWORD in .env" >&2
  exit 1
fi

# export ES_HOST
# export ES_API_KEY

# Derive KIBANA_URL from ES_HOST if not set
if [[ -z "${KIBANA_URL:-}" ]]; then
  _base="${ES_HOST%/}"
  if [[ "$_base" =~ :9200$ ]]; then
    KIBANA_URL="${_base/:9200/:5601}"
  else
    KIBANA_URL="${_base}:5601"
  fi
fi
# export KIBANA_URL

if [[ -n "${ES_HOST_BULK:-}" ]]; then
  export ES_HOST_BULK
fi

# Check Python 3.9+
if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found. Install Python 3.9 or later." >&2
  exit 1
fi

py_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
py_major=$(echo "$py_version" | cut -d. -f1)
py_minor=$(echo "$py_version" | cut -d. -f2)

if [[ "$py_major" -lt 3 ]] || { [[ "$py_major" -eq 3 ]] && [[ "$py_minor" -lt 9 ]]; }; then
  echo "ERROR: Python 3.9+ required, found $py_version" >&2
  exit 1
fi
echo "Python $py_version OK"

# Install dependencies
if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
  echo "Installing Python dependencies..."
  pip install -q -r "$SCRIPT_DIR/requirements.txt"
fi

echo "ES_HOST:    $ES_HOST"
echo "KIBANA_URL: $KIBANA_URL"
[[ -n "${ES_HOST_BULK:-}" ]] && echo "ES_HOST_BULK: $ES_HOST_BULK"
[[ -n "${ES_USERNAME:-}" ]]  && echo "Auth:       username/password (${ES_USERNAME})"
[[ -z "${ES_USERNAME:-}" ]]  && echo "Auth:       API key"

# Wait for Kibana readiness (60 × 5s = 5 min)
echo "Checking Kibana readiness..."
kibana_ready=false
for i in $(seq 1 60); do
  if curl -sf -m 5 -o /dev/null \
      -H "Authorization: ApiKey ${ES_API_KEY}" \
      "${KIBANA_URL}/api/status" 2>/dev/null; then
    echo "Kibana ready"
    kibana_ready=true
    break
  fi
  echo "Waiting for Kibana... ($i/60)"
  sleep 5
done

if [[ "$kibana_ready" == false ]]; then
  echo "ERROR: Kibana did not become ready within 5 minutes." >&2
  exit 1
fi

stage_end

# ═════════════════════════════════════════════════════════════════════════════
# [1b] Security view
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "=== Setting Kibana default to Security view ==="
curl -sf -m 10 -o /dev/null \
  -X POST "${KIBANA_URL}/api/kibana/settings" \
  -H "Authorization: ApiKey ${ES_API_KEY}" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -H "elastic-api-version: 2023-10-31" \
  -d '{"changes":{"defaultRoute":"/app/security"}}' \
  && echo "Security view set" \
  || echo "WARNING: Could not set Security view (non-fatal)"

# ═════════════════════════════════════════════════════════════════════════════
# [2/9] Schema
# ═════════════════════════════════════════════════════════════════════════════
stage_begin "[2/9] Schema"
python3 -m lab.schema
stage_end

# ═════════════════════════════════════════════════════════════════════════════
# [3/9] Rules
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$SKIP_RULES" == true ]]; then
  echo ""
  echo "=== [3/9] Rules === (skipped via --skip-rules)"
else
  stage_begin "[3/9] Rules"
  python3 -m lab.rules
  stage_end
fi

# ═════════════════════════════════════════════════════════════════════════════
# [4/9] Load historical data
# ═════════════════════════════════════════════════════════════════════════════
stage_begin "[4/9] Load historical data"
python3 -m lab.load_data
stage_end

# ═════════════════════════════════════════════════════════════════════════════
# [5/9] Read campaign metadata
# ═════════════════════════════════════════════════════════════════════════════
stage_begin "[5/9] Read campaign metadata"

META=$(python3 -c "
from lab.esclient import make_es_client, load_env
import json
e = load_env()
es = make_es_client(e['ES_HOST'], e['ES_API_KEY'], e.get('ES_HOST_BULK'))
r = es.search(index='workshop-meta', size=1)
print(json.dumps(r['hits']['hits'][0]['_source']))
")

CAMPAIGN_START=$(echo "$META" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['campaign_start_ms'])")
CAMPAIGN_END=$(echo "$META"   | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['campaign_end_ms'])")

CAMPAIGN_START_HUMAN=$(python3 -c "
import datetime, sys
ms = int(sys.argv[1])
dt = datetime.datetime.utcfromtimestamp(ms / 1000)
print(dt.strftime('%Y-%m-%d %H:%M'))
" "$CAMPAIGN_START")

CAMPAIGN_END_HUMAN=$(python3 -c "
import datetime, sys
ms = int(sys.argv[1])
dt = datetime.datetime.utcfromtimestamp(ms / 1000)
print(dt.strftime('%Y-%m-%d %H:%M'))
" "$CAMPAIGN_END")

echo "Campaign start: $CAMPAIGN_START_HUMAN UTC  ($CAMPAIGN_START ms)"
echo "Campaign end:   $CAMPAIGN_END_HUMAN UTC  ($CAMPAIGN_END ms)"

stage_end

# ═════════════════════════════════════════════════════════════════════════════
# [6/9] Backfill
# ═════════════════════════════════════════════════════════════════════════════
stage_begin "[6/9] Backfill"
python3 -m lab.backfill
stage_end

# ═════════════════════════════════════════════════════════════════════════════
# [7/9] Live replay
# ═════════════════════════════════════════════════════════════════════════════
if [[ "$NO_REPLAY" == true ]]; then
  echo ""
  echo "=== [7/9] Live replay === (skipped via --no-replay)"
else
  stage_begin "[7/9] Live replay"
  python3 -m lab.replay start
  stage_end
fi

# ═════════════════════════════════════════════════════════════════════════════
# [8/9] Verify
# ═════════════════════════════════════════════════════════════════════════════
stage_begin "[8/9] Verify"
python3 -m lab.verify
stage_end

# ═════════════════════════════════════════════════════════════════════════════
# [9/9] Summary
# ═════════════════════════════════════════════════════════════════════════════
TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$(( TOTAL_END - TOTAL_START ))

echo ""
echo "=== Setup Complete ==="
echo "Elapsed: $(format_elapsed "$TOTAL_ELAPSED")"
echo "In Kibana: set time picker to 'Last 9 days'"
echo "Attack campaign: $CAMPAIGN_START_HUMAN → $CAMPAIGN_END_HUMAN UTC"
