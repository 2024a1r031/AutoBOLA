# Prove, Patch, Re-prove: Automated BOLA/IDOR Scanner (Prototype, Phase 1)

A scanner that finds **Broken Object Level Authorization (BOLA/IDOR)** bugs in REST APIs.
Phase 1 (this repo, ~50%): a reliable detector. Phase 2 (planned): AI-assisted fixes and Docker re-verification.

> **Ethical use:** only run this against systems you own or have written permission to test
> (your own apps, VAmPI, crAPI on localhost). The tool refuses non-local targets unless you add `--i-have-permission`.

## What BOLA is (30 seconds)
User B changes `/orders/101` to `/orders/102` and sees (or edits, or deletes) user A's order,
because the server never checks who owns it. It is #1 in the OWASP API Security Top 10.

## How the scanner works
1. **Read the OpenAPI spec**: find object-level endpoints like `/orders/{order_id}` and their methods.
2. **Create a fresh victim and attacker** for every single test (tests never disturb each other).
3. **Victim creates an object** containing a unique secret marker.
4. **Baseline check**: the owner must be able to read their own object (otherwise the test is skipped).
5. **Attack** as the attacker, then **confirm with evidence**, not just a status code:

| Method | Confirmed only if... |
|---|---|
| GET | attacker's response contains the victim's marker (and a non-existent id does not) |
| PUT / PATCH | the victim re-reads the object and the attacker's value is really there (resource-state check) |
| DELETE | the victim re-reads the object and it is really gone (resource-state check) |

Detection is **deterministic**. No LLM is used to decide whether something is vulnerable.

## Why state checks matter ("decoy" endpoints)
Some APIs answer `200`/`204` but silently ignore the request. A scanner that only reads status codes
raises a false alarm. We compare against a **naive status-code-only detector** in every run.

## Project structure
```
target_api/app.py      our own test API (VULNERABLE=1 or 0), includes decoy endpoints
scanner/               spec_parser, client, detector (core), metrics
configs/               own_api.yaml, vampi.yaml (how to log in / create objects)
labels.yaml            ground truth: which endpoint is really vulnerable
scan.py                run the scanner on one target
evaluate.py            combine all runs into one confusion matrix
tests/                 unit tests (pytest)
```

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

## Run it
```bash
# Terminal 1: our API, vulnerable mode      Terminal 2: our API, secure mode
VULNERABLE=1 uvicorn target_api.app:app --port 8000
VULNERABLE=0 uvicorn target_api.app:app --port 8001

# Terminal 3: scan both and evaluate
python scan.py --config configs/own_api.yaml --base-url http://127.0.0.1:8000 --labels own-api/vulnerable
python scan.py --config configs/own_api.yaml --base-url http://127.0.0.1:8001 --labels own-api/secure
python evaluate.py
```

VAmPI (Docker):
```bash
docker run -d -p 5000:5000 -e vulnerable=1 erev0s/vampi:latest
docker run -d -p 5001:5000 -e vulnerable=0 erev0s/vampi:latest
python scan.py --config configs/vampi.yaml --base-url http://127.0.0.1:5000 --labels vampi/vulnerable
python scan.py --config configs/vampi.yaml --base-url http://127.0.0.1:5001 --labels vampi/secure
python evaluate.py
```
Run unit tests: `pytest`

## Status
- [x] Own vulnerable + secure test API (with decoys)
- [x] OpenAPI spec parsing
- [x] Multi-user testing: read, update, delete
- [x] Response analysis, resource-state checks, control checks
- [x] Evaluation: TP/FP/FN/TN, precision, recall, FP rate (own API + VAmPI)
- [ ] Database snapshot/rollback for destructive tests
- [ ] AI-assisted patch generation
- [ ] Docker sandbox re-verification of fixes
- [ ] HTML report
- [ ] OWASP crAPI evaluation

## Limitations (honest)
- Each target needs a small config (how to log in, how to create an object). The spec alone is not enough yet.
- The evaluation set is small (a handful of endpoints). Results are a prototype, not a benchmark.
- Our own API contains decoy endpoints we designed ourselves; VAmPI is the independent check.

## References
- OWASP API Security Top 10: https://owasp.org/API-Security/
- VAmPI: https://github.com/erev0s/VAmPI
- OWASP crAPI: https://github.com/OWASP/crAPI
