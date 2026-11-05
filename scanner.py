
import httpx
import json
from datetime import datetime, timezone

BASE_URL = "http://127.0.0.1:8000"

ALICE_TOKEN = "rahul-token"
BOB_ORDER_ID = 202

headers = {
    "Authorization": f"Bearer {ALICE_TOKEN}"
}


def test_endpoint(vulnerable):
    url = f"{BASE_URL}/orders/{BOB_ORDER_ID}"

    result = {
        "endpoint": f"GET /orders/{BOB_ORDER_ID}",
        "test_mode": "vulnerable" if vulnerable else "secure",
        "test_user": "alice",
        "resource_owner": "bob",
        "http_status": None,
        "result": "INCONCLUSIVE",
        "evidence": "",
        "recommendation": (
            "Verify that the authenticated user owns the requested "
            "resource before returning or modifying it."
        )
    }

    try:
        response = httpx.get(
            url,
            headers=headers,
            params={"vulnerable": vulnerable},
            timeout=5.0
        )

        result["http_status"] = response.status_code

        try:
            data = response.json()
        except ValueError:
            data = {}

        if (
            response.status_code == 200
            and data.get("owner") == "bob"
            and data.get("id") == BOB_ORDER_ID
        ):
            result["result"] = "VULNERABLE"
            result["evidence"] = (
                "Alice received order 202, which belongs to Bob."
            )

        elif response.status_code == 403:
            result["result"] = "BLOCKED"
            result["evidence"] = (
                "The API denied Alice access to Bob's order."
            )

        else:
            result["evidence"] = (
                "The response did not match the expected test result. "
                "Manual review is needed."
            )

    except httpx.RequestError as error:
        result["evidence"] = (
            f"Could not connect to the test API: {error}"
        )

    print(f"\nEndpoint: {result['endpoint']}")
    print(f"Test mode: {result['test_mode']}")
    print(f"HTTP status: {result['http_status']}")
    print(f"Result: {result['result']}")
    print(f"Evidence: {result['evidence']}")

    return result


if __name__ == "__main__":
    report = {
        "project": "AutoBOLA",
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "tests": [
            test_endpoint(True),
            test_endpoint(False)
        ]
    }

    with open("report.json", "w") as file:
        json.dump(report, file, indent=4)

    print("\nDetailed report saved to report.json")


