"""
Step 1 of the scanner: READ THE API SPEC (OpenAPI/Swagger).
We list every operation whose path contains an object id like /orders/{order_id}.
These are the only places where BOLA can happen.
"""
import json
import httpx
import yaml

TESTED_METHODS = {"get", "put", "patch", "delete"}


def load_spec(source):
    """source can be a URL (http://.../openapi.json) or a local file path."""
    if source.startswith("http"):
        text = httpx.get(source, timeout=10).text
    else:
        with open(source, encoding="utf-8") as f:
            text = f.read()
    try:
        return json.loads(text)
    except ValueError:
        return yaml.safe_load(text)


def list_operations(spec):
    """Return [{'method': 'GET', 'path': '/orders/{order_id}'}, ...] for object-level endpoints."""
    ops = []
    for path, item in (spec.get("paths") or {}).items():
        if "{" not in path:
            continue
        for method in item:
            if method.lower() in TESTED_METHODS:
                ops.append({"method": method.upper(), "path": path})
    return ops
