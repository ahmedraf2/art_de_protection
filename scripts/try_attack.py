#!/usr/bin/env python3
"""
Try the attack yourself: tamper with the academic records, then see which build
notices. Runs the SAME attack against the vuln build (:3000) and the secure
build (:3001) and prints the outcome side by side.

Attacker model: someone who got WRITE access to the database file (server
access, a stolen backup, a misconfigured share...). They can read this project's
source code, and they have their own Ethereum account, but NOT the issuer's
private key (keys/eth_issuer.key).

Run it from the project folder, with both apps running on a fresh state:

    python3 scripts/try_attack.py
    docker compose exec secure python3 scripts/try_attack.py     (no local Python deps needed)

It modifies both databases. Reset afterwards with:

    docker compose restart vuln secure        (or rerun both apps with RESET_DB=1)
"""

import os
import sys
import json
import sqlite3
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from web3 import Web3
from web3.exceptions import ContractCustomError
from eth_account import Account

import eth_ledger          # the attacker reads the source: same hash function as the app

V = os.environ.get("V", "http://127.0.0.1:3000")
S = os.environ.get("S", "http://127.0.0.1:3001")
RPC = "http://127.0.0.1:8545"
# Anvil's account #1: the attacker's own Ethereum account (not the issuer).
ATTACKER_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

ALICE, MATH, FORGED = 4, 1, "20.00"
FAKE_CERT = (ALICE, "PhD in Computer Science", "A+", "2026-01-01")

RED, GREEN, YELLOW, BOLD, DIM, END = "\033[31m", "\033[32m", "\033[33m", "\033[1m", "\033[2m", "\033[0m"


# --- small helpers -------------------------------------------------------
def api(base, path, token=None, body=None):
    req = urllib.request.Request(base + path, method="POST" if body else "GET")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    if body:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(body).encode()
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def login(base):
    try:
        _, d = api(base, "/api/login", body={"username": "alice", "password": "password1"})
    except urllib.error.URLError:
        sys.exit(f"{RED}cannot reach {base} — start the apps first (docker compose up){END}")
    return d["token"]


def db(name, sql, params=()):
    conn = sqlite3.connect(os.path.join(HERE, f"sms_{name}.db"))
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def math_grade(base, tok):
    return next(g["grade"] for g in api(base, "/api/my/grades", tok)[1]["grades"] if g["code"] == "MATH")


def step(n, title, what):
    print(f"\n{BOLD}━━ Step {n}: {title} ━━{END}\n{DIM}{what}{END}")


def say(build, attacker_won, text):
    color, mark = (RED, "✘") if attacker_won else (GREEN, "✔")
    print(f"  {build:<7} {color}{mark} {text}{END}")


# --- the attack ----------------------------------------------------------
def main():
    tv, ts = login(V), login(S)

    # Refuse to run on an already-tampered state: results would be confusing.
    _, integ = api(S, "/api/grades/integrity", ts)
    if integ.get("available") is False:
        sys.exit(f"{RED}secure build cannot reach the ledger: {integ.get('error')}{END}")
    if math_grade(V, tv) != "14.00" or not all(r["ok"] for r in integ["rows"]):
        sys.exit(f"{YELLOW}Not a fresh state. Reset first:  docker compose restart vuln secure{END}")

    print(f"{BOLD}Attacker: has write access to the database file, but not the issuer key.{END}")

    step(1, "Before the attack", "Alice's Mathematics grade as each app shows it.")
    print(f"  vuln    {math_grade(V, tv)}/20")
    print(f"  secure  {math_grade(S, ts)}/20")

    # ------------------------------------------------------------------
    step(2, "Change a grade directly in the database",
         f"UPDATE grades SET grade='{FORGED}' WHERE student_id={ALICE} AND course_id={MATH}")
    for name in ("vuln", "secure"):
        db(name, "UPDATE grades SET grade=? WHERE student_id=? AND course_id=?", (FORGED, ALICE, MATH))

    code, _ = api(V, "/api/grades/integrity", tv)
    say("vuln", True, f"shows {math_grade(V, tv)}/20 and has no way to check it "
                      f"(integrity endpoint: HTTP {code}) → NOT DETECTED")
    row = next(r for r in api(S, "/api/grades/integrity", ts)[1]["rows"] if r["code"] == "MATH")
    say("secure", row["ok"], "DB hash ≠ contract hash → TAMPERING DETECTED")
    print(f"{DIM}          DB hash       {row['db_hash']}\n"
          f"          contract hash {row['chain_hash']}{END}")

    # ------------------------------------------------------------------
    step(3, "Insert a fake diploma into the database",
         f"INSERT INTO certifications ... '{FAKE_CERT[1]}' for alice, with a made-up signature")
    for name in ("vuln", "secure"):
        db(name, "INSERT INTO certifications (student_id,title,grade,issued_date,signature) "
                 "VALUES (?,?,?,?,'ZmFrZXNpZw==')", FAKE_CERT)

    fake = lambda base, tok: next(c for c in api(base, "/api/certifications", tok)[1]["certifications"]
                                  if c["title"] == FAKE_CERT[1])
    c = fake(V, tv)
    say("vuln", c["verified"], f"verified={c['verified']} → fake diploma ACCEPTED as genuine")
    c = fake(S, ts)
    say("secure", c["verified"] or c["on_chain"],
        f"verified={c['verified']}, on_chain={c['on_chain']} → fake diploma REJECTED")

    # ------------------------------------------------------------------
    step(4, "Cover the tracks: write the forged hash into the contract",
         "The attacker computes the hash of the forged grade exactly like the app does,\n"
         "then sends anchorGrade(...) signed with THEIR OWN key (anvil account #1).")
    print(f"  vuln    {DIM}nothing to cover: there is no ledger, step 2 already went unnoticed{END}")

    w3 = Web3(Web3.HTTPProvider(RPC))
    dep = eth_ledger.deployment()
    with open(eth_ledger.ARTIFACT_PATH) as f:
        abi = json.load(f)["abi"]
    ledger = w3.eth.contract(address=dep["address"], abi=abi)
    attacker = Account.from_key(ATTACKER_KEY)
    forged_hash = eth_ledger.grade_hash(MATH, ALICE, FORGED)
    fn = ledger.functions.anchorGrade(MATH, ALICE, bytes.fromhex(forged_hash[2:]))
    print(f"{DIM}          attacker {attacker.address}\n"
          f"          issuer   {dep['issuer']}\n"
          f"          forged   {forged_hash}{END}")

    # Why will it fail? Simulate the call and decode the custom error.
    errors = {"0x" + Web3.keccak(text=f"{e['name']}()")[:4].hex(): e["name"]
              for e in abi if e["type"] == "error"}
    try:
        fn.call({"from": attacker.address})
        reason = "none (call succeeded!)"
    except ContractCustomError as e:
        reason = errors.get(e.data, e.data) + "()"

    # Send it for real anyway (fixed gas, so it is mined instead of refused up front).
    tx = fn.build_transaction({"from": attacker.address, "gas": 100_000,
                               "nonce": w3.eth.get_transaction_count(attacker.address)})
    receipt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(attacker.sign_transaction(tx).raw_transaction))
    say("secure", receipt.status == 1,
        f"transaction mined in block {receipt.blockNumber} with status {receipt.status} "
        f"(REVERTED: {reason})")

    row = next(r for r in api(S, "/api/grades/integrity", ts)[1]["rows"] if r["code"] == "MATH")
    say("secure", row["ok"], "contract hash unchanged → grade still flagged as TAMPERED")

    # ------------------------------------------------------------------
    print(f"\n{BOLD}━━ Result ━━{END}")
    print(f"  {'attack':<38}{'vuln build':<22}secure build")
    print(f"  {'change a grade in the DB':<38}{RED}{'not detected':<22}{GREEN}detected{END}")
    print(f"  {'insert a fake diploma in the DB':<38}{RED}{'accepted':<22}{GREEN}rejected{END}")
    print(f"  {'rewrite the ledger to hide it':<38}{DIM}{'(no ledger)':<22}{END}{GREEN}reverted: NotIssuer{END}")
    print(f"\n{DIM}Note: the secure build DETECTS the tampering, it does not undo it. The DB still\n"
          f"says {FORGED}; the contract proves that value was never issued.{END}")
    print(f"\nReset:  docker compose restart vuln secure")


if __name__ == "__main__":
    main()
