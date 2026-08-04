# Agent Intrusion Lab

Hands-on lab (~2 hours): hunt the **first publicly confirmed autonomous AI agent intrusion** using Elastic Security — K8s audit logs, prebuilt SIEM rules, and Attack Discovery triage.

**Defensive / educational use only.**

Based on Elastic Security Labs — *"Exploring the Hugging Face Breach: mapping AI agent tactics to Elastic Defend"* (2026-07-31).

---

## Files

| Path | Use |
|---|---|
| [LAB_GUIDE.md](./LAB_GUIDE.md) | Lab guide — agenda, 8 ES\|QL queries, challenges, debrief |
| [setup.sh](./setup.sh) | One-command cluster setup (install rules, load data, backfill, verify) |
| [.env.example](./.env.example) | Credential template — copy to `.env` and fill in |
| [requirements.txt](./requirements.txt) | Python dependencies |
| [lab/](./lab/) | Python modules: schema, data gen, rules, backfill, verify |
| [reference/](./reference/) | Hunt queries, TTP mapping, prebuilt rule JSON |

---

## What attendees build

| Skill | Where |
|---|---|
| Read 330,000 K8s audit log events without drowning in noise | Challenges 1–2 |
| Distinguish agent-driven from human-driven intrusions by behavioral fingerprint | Q2 — deny ratio × breadth |
| Understand the Day 2 quiet trap (agent rate-modulation defeats velocity detection) | Challenge 1 |
| Operate prebuilt Elastic SIEM rules: EQL sequences, ES\|QL correlations, new\_terms | Challenge 3 |
| Triage a multi-stage breach narrative with Attack Discovery in under 90 seconds | Challenge 4 |

---

## Start

1. Copy `.env.example` → `.env` and fill in `ES_HOST`, `KIBANA_URL`, `ES_API_KEY`.
2. Run setup:
   ```bash
   pip install -r requirements.txt
   bash setup.sh
   ```
3. Open the [lab guide](./LAB_GUIDE.md).

### Setup stages

| Stage | What it does |
|---|---|
| Preflight | Checks connectivity and stack version (≥ 9.3.0 required) |
| Schema | Creates data stream templates for 6 Elastic integration indices |
| Prebuilt rules | Installs all Elastic prebuilt detection rules (~2,000) |
| Enable rules | Enables the 36 rules mapped to the Hugging Face breach |
| Load data | Bulk-indexes 330,000 synthetic events over a 5-day campaign window |
| Backfill | Schedules manual rule runs to materialise alerts from historical data |
| Verify | 9-check gate — exits non-zero on failure |

---

## Requirements

- Elastic Cloud Hosted (ECH) ≥ 9.3.0, or Serverless Security project
- Python 3.10+
- An API key with cluster-admin privileges (for schema + rule install)

---

## Elastic docs

- [Elastic Security prebuilt rules](https://www.elastic.co/guide/en/security/current/prebuilt-rules.html)
- [ES|QL reference](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html)
- [Attack Discovery](https://www.elastic.co/guide/en/security/current/attack-discovery.html)
- [Kubernetes integration](https://docs.elastic.co/integrations/kubernetes)
- [Elastic Defend deployment](https://www.elastic.co/guide/en/security/current/install-endpoint.html)
- [Elastic Security Labs: Hugging Face breach analysis](https://www.elastic.co/security-labs/ai-agent-attack-detection-hugging-face-breach)

---

## Disclaimer

This lab uses **purpose-built synthetic telemetry** — not anonymised production data or real breach data. All techniques, queries, and rule mappings are provided for **defensive security education only**. The 330,000 events reproduce observable patterns from the public Elastic Security Labs analysis; they are not a replay of Hugging Face's internal telemetry.
