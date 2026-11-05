
from fastapi import FastAPI, Header, HTTPException

app = FastAPI(title="AutoBOLA Test API")

# Demo tokens only — not real authentication
USERS = {
    "rahul-token": "rahul",
    "priya-token": "priya"
}

ORDERS = {
    101: {"id": 101, "owner": "rahul", "item": "Rahul's book"},
    202: {"id": 202, "owner": "priya", "item": "Priya's laptop"}
}


@app.get("/")
def home():
    return {"message": "AutoBOLA test API is running"}


@app.get("/orders/{order_id}")
def get_order(
    order_id: int,
    authorization: str | None = Header(default=None),
    vulnerable: bool = False
):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Login required")

    token = authorization.replace("Bearer ", "", 1)
    username = USERS.get(token)

    if username is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    order = ORDERS.get(order_id)

    if order is None:
        raise HTTPException(status_code=404, detail="Order not found")

    # Vulnerable mode skips the ownership check
    if not vulnerable and order["owner"] != username:
        raise HTTPException(status_code=403, detail="Access denied")

    return order

from pathlib import Path
import subprocess
import sys
import json

from fastapi.responses import FileResponse
from fastapi import HTTPException


PROJECT_DIR = Path(__file__).resolve().parent


@app.get("/dashboard")
def dashboard():
    return FileResponse(PROJECT_DIR / "dashboard.html")


@app.post("/scan")
def run_scan():
    scanner_path = PROJECT_DIR / "scanner.py"
    report_path = PROJECT_DIR / "report.json"

    try:
        result = subprocess.run(
            [sys.executable, str(scanner_path)],
            cwd=str(PROJECT_DIR),
            capture_output=True,
            text=True,
            timeout=20
        )

        if result.returncode != 0:
            raise HTTPException(
                status_code=500,
                detail="Scanner failed: " + result.stderr[-1500:]
            )

        if not report_path.exists():
            raise HTTPException(
                status_code=500,
                detail="Scanner did not create report.json"
            )

        with open(report_path, "r") as file:
            report = json.load(file)

        return {
            "message": "Scan completed",
            "report": report,
            "terminal_output": result.stdout
        }

    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=504,
            detail="Scan timed out"
        )
