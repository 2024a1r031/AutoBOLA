"""Small helper functions used everywhere."""
import re
import secrets

PARAM_RE = re.compile(r"\{[^}/]+\}")


def rand(n=8):
    """Random hex string, used for unique usernames, markers, etc."""
    return secrets.token_hex(n)[:n]


def fill(obj, **variables):
    """Replace {placeholders} inside strings (also inside dicts/lists).
    Only the keys we pass are replaced, so path params like {order_id} stay untouched."""
    if isinstance(obj, str):
        for key, value in variables.items():
            obj = obj.replace("{" + key + "}", str(value))
        return obj
    if isinstance(obj, dict):
        return {k: fill(v, **variables) for k, v in obj.items()}
    if isinstance(obj, list):
        return [fill(v, **variables) for v in obj]
    return obj


def with_id(path_template, obj_id):
    """/orders/{order_id} + 5  ->  /orders/5"""
    return PARAM_RE.sub(str(obj_id), path_template, count=1)


def dig(data, dotted):
    """dig({'a': {'b': 1}}, 'a.b') -> 1. Returns None if anything is missing."""
    cur = data
    for part in dotted.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur
