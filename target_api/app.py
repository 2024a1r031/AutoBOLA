"""
target_api/app.py
-----------------
OUR OWN test API. Run it in two modes:
    VULNERABLE=1  -> orders and invoices have BOLA bugs (no ownership check)
    VULNERABLE=0  -> everything is secure

The /notes endpoints are ALWAYS secure on purpose. Their PUT and DELETE are "decoys":
they return HTTP 200 even for a non-owner, but silently do nothing.
A scanner that only looks at status codes will wrongly call them vulnerable.
Our scanner checks the real state afterwards, so it is not fooled.
"""
import os
import secrets
import itertools
from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel

VULNERABLE = os.getenv("VULNERABLE", "1") == "1"
app = FastAPI(title="Demo Target API", version="1.0")

USERS = {}      # username -> password
TOKENS = {}     # token -> username
ORDERS = {}
INVOICES = {}
NOTES = {}
_ids = itertools.count(1)


class Cred(BaseModel):
    username: str
    password: str


class OrderIn(BaseModel):
    item: str
    note: str = ""


class OrderUpdate(BaseModel):
    note: str


class InvoiceIn(BaseModel):
    amount: int
    memo: str = ""


class NoteIn(BaseModel):
    text: str


def current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing token")
    user = TOKENS.get(authorization.split(" ", 1)[1])
    if not user:
        raise HTTPException(401, "Invalid token")
    return user


def check_owner(obj, user):
    """The ownership check. Vulnerable mode skips it (that IS the bug)."""
    if not VULNERABLE and obj["owner"] != user:
        raise HTTPException(403, "Forbidden")


@app.get("/")
def home():
    return {"app": "demo target", "vulnerable_mode": VULNERABLE}


@app.post("/register")
def register(c: Cred):
    if c.username in USERS:
        raise HTTPException(400, "User exists")
    USERS[c.username] = c.password
    return {"status": "registered"}


@app.post("/login")
def login(c: Cred):
    if USERS.get(c.username) != c.password:
        raise HTTPException(401, "Bad credentials")
    token = secrets.token_hex(16)
    TOKENS[token] = c.username
    return {"access_token": token}


# ---------------- orders (vulnerable when VULNERABLE=1) ----------------
@app.post("/orders")
def create_order(o: OrderIn, user=Depends(current_user)):
    oid = next(_ids)
    ORDERS[oid] = {"id": oid, "owner": user, "item": o.item, "note": o.note}
    return ORDERS[oid]


@app.get("/orders/{order_id}")
def get_order(order_id: int, user=Depends(current_user)):
    o = ORDERS.get(order_id)
    if not o:
        raise HTTPException(404, "Order not found")
    check_owner(o, user)
    return o


@app.put("/orders/{order_id}")
def update_order(order_id: int, u: OrderUpdate, user=Depends(current_user)):
    o = ORDERS.get(order_id)
    if not o:
        raise HTTPException(404, "Order not found")
    check_owner(o, user)
    o["note"] = u.note
    return o


@app.delete("/orders/{order_id}")
def delete_order(order_id: int, user=Depends(current_user)):
    o = ORDERS.get(order_id)
    if not o:
        raise HTTPException(404, "Order not found")
    check_owner(o, user)
    del ORDERS[order_id]
    return {"status": "deleted"}


# ---------------- invoices (read only, vulnerable when VULNERABLE=1) ----------------
@app.post("/invoices")
def create_invoice(i: InvoiceIn, user=Depends(current_user)):
    iid = next(_ids)
    INVOICES[iid] = {"id": iid, "owner": user, "amount": i.amount, "memo": i.memo}
    return INVOICES[iid]


@app.get("/invoices/{invoice_id}")
def get_invoice(invoice_id: int, user=Depends(current_user)):
    i = INVOICES.get(invoice_id)
    if not i:
        raise HTTPException(404, "Invoice not found")
    check_owner(i, user)
    return i


# ---------------- notes (ALWAYS secure; PUT/DELETE are decoys) ----------------
@app.post("/notes")
def create_note(n: NoteIn, user=Depends(current_user)):
    nid = next(_ids)
    NOTES[nid] = {"id": nid, "owner": user, "text": n.text}
    return NOTES[nid]


@app.get("/notes/{note_id}")
def get_note(note_id: int, user=Depends(current_user)):
    n = NOTES.get(note_id)
    if not n:
        raise HTTPException(404, "Note not found")
    if n["owner"] != user:
        raise HTTPException(403, "Forbidden")
    return n


@app.put("/notes/{note_id}")
def update_note(note_id: int, n: NoteIn, user=Depends(current_user)):
    note = NOTES.get(note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    if note["owner"] == user:          # only the owner really changes it
        note["text"] = n.text
    return {"status": "ok"}            # but ALWAYS answers 200 (decoy)


@app.delete("/notes/{note_id}")
def delete_note(note_id: int, user=Depends(current_user)):
    note = NOTES.get(note_id)
    if not note:
        raise HTTPException(404, "Note not found")
    if note["owner"] == user:
        del NOTES[note_id]
    return {"status": "deleted"}       # decoy: says deleted, did nothing
