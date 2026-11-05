from scanner.utils import fill, with_id, dig
from scanner.spec_parser import list_operations
from scanner.metrics import confusion, scores


def test_fill_only_replaces_known_keys():
    assert fill("/x/{order_id}/{marker}", marker="M1") == "/x/{order_id}/M1"
    assert fill({"a": ["{new}"]}, new="Z") == {"a": ["Z"]}


def test_with_id():
    assert with_id("/orders/{order_id}", 5) == "/orders/5"


def test_dig():
    assert dig({"a": {"b": 7}}, "a.b") == 7
    assert dig({"a": 1}, "x.y") is None


def test_list_operations_only_object_level():
    spec = {"paths": {
        "/orders": {"post": {}},
        "/orders/{order_id}": {"get": {}, "put": {}, "delete": {}, "parameters": []},
    }}
    ops = {(o["method"], o["path"]) for o in list_operations(spec)}
    assert ops == {("GET", "/orders/{order_id}"), ("PUT", "/orders/{order_id}"), ("DELETE", "/orders/{order_id}")}


def test_confusion_and_scores():
    rows = [
        {"truth": "vulnerable", "v": True},    # TP
        {"truth": "secure", "v": True},        # FP
        {"truth": "vulnerable", "v": False},   # FN
        {"truth": "secure", "v": False},       # TN
    ]
    assert confusion(rows, "v") == (1, 1, 1, 1)
    s = scores(1, 1, 1, 1)
    assert s["precision"] == 0.5 and s["recall"] == 0.5 and s["accuracy"] == 0.5
