"""
Integrity ledger on a local Ethereum node (secure build only).

Grades and certificates live in SQLite; this module anchors their SHA-256 hashes
in the GradeLedger smart contract (contracts/src/GradeLedger.sol) running on a
local anvil node. The contract only accepts writes from the issuer key, which
lives in keys/eth_issuer.key — so someone who can edit the database still
cannot make the ledger agree with a tampered record.

    anchor_grade(course_id, student_id, grade_hash)    write  (issuer only)
    get_grade(course_id, student_id) -> hash | None     read
    anchor_cert(fingerprint)                           write  (issuer only)
    is_cert_anchored(fingerprint) -> bool              read

Every failure (node down, contract missing, transaction rejected) raises
LedgerUnavailable, which app.py turns into an HTTP 503.

Before the first run:   anvil --host 127.0.0.1          (separate terminal)
                        cd contracts && forge build
"""

import os
import json
import hashlib
import threading
from urllib.parse import urlparse

import requests
from web3 import Web3
from web3.exceptions import BadFunctionCallOutput
from eth_account import Account

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_DIR = os.path.join(HERE, "keys")
ISSUER_KEY_PATH = os.path.join(KEY_DIR, "eth_issuer.key")
DEPLOYMENT_PATH = os.path.join(KEY_DIR, "deployment.json")
ARTIFACT_PATH = os.path.join(HERE, "contracts", "out", "GradeLedger.sol", "GradeLedger.json")

RPC_URL = os.environ.get("ETH_RPC_URL", "http://127.0.0.1:8545")
CHAIN_ID = 31337                  # anvil's local dev chain id

# Anvil's default account #0. Its key is public (derived from the well-known
# test mnemonic), so it is used ONLY as a faucet to fund our own issuer key.
ANVIL_FUNDER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"


class LedgerUnavailable(Exception):
    """The ledger could not be reached or refused the operation."""


# --- hashing -------------------------------------------------------------
def grade_hash(course_id, student_id, grade) -> str:
    """SHA-256 of the canonical JSON of a grade row, as stored in the DB."""
    payload = json.dumps({"course_id": int(course_id), "student_id": int(student_id),
                          "grade": grade}, sort_keys=True, separators=(",", ":"))
    return "0x" + hashlib.sha256(payload.encode()).hexdigest()


def _b32(h: str) -> bytes:
    """'abcd…' or '0xabcd…' (64 hex digits) -> 32 raw bytes for the contract."""
    return bytes.fromhex(h[2:] if h.startswith("0x") else h)


# --- connection ----------------------------------------------------------
_w3 = None
_contract = None
_tx_lock = threading.Lock()       # Flask is threaded; one sender -> one tx at a time


def _connect() -> Web3:
    global _w3
    if _w3 is not None:
        return _w3
    # Only ever talk to a local dev node: refuse remote hosts and real networks.
    if urlparse(RPC_URL).hostname != "127.0.0.1":
        raise LedgerUnavailable(f"refusing non-local RPC endpoint {RPC_URL}")
    w3 = Web3(Web3.HTTPProvider(RPC_URL, request_kwargs={"timeout": 5},
                                exception_retry_configuration=None))
    try:
        chain_id = w3.eth.chain_id
    except Exception:
        raise LedgerUnavailable(f"no Ethereum node at {RPC_URL} — is anvil running?")
    if chain_id != CHAIN_ID:
        raise LedgerUnavailable(f"refusing chain id {chain_id} (expected {CHAIN_ID})")
    _w3 = w3
    return w3


def _artifact():
    if not os.path.exists(ARTIFACT_PATH):
        raise LedgerUnavailable("contract not compiled — run: cd contracts && forge build")
    with open(ARTIFACT_PATH) as f:
        return json.load(f)


def deployment():
    if not os.path.exists(DEPLOYMENT_PATH):
        return None
    with open(DEPLOYMENT_PATH) as f:
        return json.load(f)


def _ledger():
    """The deployed GradeLedger contract object."""
    global _contract
    if _contract is not None:
        return _contract
    w3 = _connect()
    dep = deployment()
    if not dep:
        raise LedgerUnavailable("no contract deployed — restart with RESET_DB=1")
    _contract = w3.eth.contract(address=dep["address"], abi=_artifact()["abi"])
    return _contract


def _issuer():
    """Load the issuer account, generating a fresh key on first use (0600)."""
    if not os.path.exists(ISSUER_KEY_PATH):
        os.makedirs(KEY_DIR, exist_ok=True)
        acct = Account.create()
        fd = os.open(ISSUER_KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(acct.key.hex())
    with open(ISSUER_KEY_PATH) as f:
        return Account.from_key(f.read().strip())


def _send(w3, acct, tx):
    """Sign `tx` with `acct`, send it, wait for the receipt; raise if it failed."""
    with _tx_lock:
        tx = dict(tx)
        tx.setdefault("chainId", CHAIN_ID)
        tx["nonce"] = w3.eth.get_transaction_count(acct.address, "pending")
        signed = acct.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)
    if receipt.status != 1:
        raise LedgerUnavailable(f"transaction {tx_hash.hex()} reverted")
    return receipt


def _explain(e, what):
    if isinstance(e, requests.exceptions.ConnectionError):
        return LedgerUnavailable(f"no Ethereum node at {RPC_URL} — is anvil running?")
    if isinstance(e, BadFunctionCallOutput):      # empty reply: no code at the address
        return LedgerUnavailable("contract not found on the node — restart with RESET_DB=1")
    return LedgerUnavailable(f"ledger {what} failed: {e}")


def _write(fn):
    """Call a contract write function as the issuer."""
    try:
        w3, acct = _connect(), _issuer()
        tx = fn.build_transaction({"from": acct.address})   # gas estimate fails on revert
        return _send(w3, acct, tx)
    except LedgerUnavailable:
        raise
    except Exception as e:
        raise _explain(e, "write")


def _read(fn):
    try:
        return fn.call()
    except LedgerUnavailable:
        raise
    except Exception as e:
        raise _explain(e, "read")


# --- deployment ----------------------------------------------------------
def deploy():
    """Fund the issuer from anvil #0 if needed, deploy a fresh GradeLedger and
    save its address to keys/deployment.json. Called on RESET_DB=1."""
    global _contract
    w3, acct, art = _connect(), _issuer(), _artifact()

    if w3.eth.get_balance(acct.address) < Web3.to_wei(1, "ether"):
        funder = Account.from_key(ANVIL_FUNDER_KEY)
        _send(w3, funder, {"to": acct.address, "value": Web3.to_wei(10, "ether"),
                           "gas": 21000, "gasPrice": w3.eth.gas_price})

    factory = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"]["object"])
    receipt = _send(w3, acct, factory.constructor().build_transaction({"from": acct.address}))

    dep = {"address": receipt.contractAddress, "issuer": acct.address,
           "chain_id": CHAIN_ID, "block": receipt.blockNumber}
    with open(DEPLOYMENT_PATH, "w") as f:
        json.dump(dep, f, indent=2)
    _contract = None
    return dep


def check_deployment():
    """None if the saved contract is live on the node, else a message to show."""
    dep = deployment()
    if not dep:
        return "no GradeLedger deployment found."
    try:
        w3 = _connect()
    except LedgerUnavailable as e:
        return str(e)
    if not w3.eth.get_code(dep["address"]):
        return (f"no contract at {dep['address']} — anvil was probably restarted "
                "(it keeps no state).")
    return None


# --- the four ledger operations -----------------------------------------
def anchor_grade(course_id, student_id, gh):
    return _write(_ledger().functions.anchorGrade(int(course_id), int(student_id), _b32(gh)))


def get_grade(course_id, student_id):
    h = _read(_ledger().functions.getGrade(int(course_id), int(student_id)))
    return None if h == bytes(32) else "0x" + h.hex()


def anchor_cert(fingerprint):
    return _write(_ledger().functions.anchorCertificate(_b32(fingerprint)))


def is_cert_anchored(fingerprint) -> bool:
    return _read(_ledger().functions.isCertificateAnchored(_b32(fingerprint)))


# --- explorer ------------------------------------------------------------
def info():
    """Contract address, issuer and every anchored event (for the explorer)."""
    try:
        w3, c, dep = _connect(), _ledger(), deployment()
        logs = (list(c.events.GradeAnchored().get_logs(from_block=dep["block"])) +
                list(c.events.CertificateAnchored().get_logs(from_block=dep["block"])))
        logs.sort(key=lambda e: (e.blockNumber, e.logIndex))
        times = {}
        events = []
        for e in logs:
            if e.blockNumber not in times:
                times[e.blockNumber] = w3.eth.get_block(e.blockNumber).timestamp
            a = e.args
            ev = {"type": "grade" if e.event == "GradeAnchored" else "certification",
                  "block": e.blockNumber, "timestamp": times[e.blockNumber],
                  "tx_hash": "0x" + e.transactionHash.hex(), "sender": a.sender}
            if ev["type"] == "grade":
                ev.update(course_id=a.courseId, student_id=a.studentId,
                          hash="0x" + a.gradeHash.hex())
            else:
                ev["hash"] = "0x" + a.fingerprint.hex()
            events.append(ev)
        return {"chain_id": CHAIN_ID, "contract": dep["address"],
                "issuer": _read(c.functions.issuer()),
                "block_number": w3.eth.block_number, "events": events}
    except LedgerUnavailable:
        raise
    except Exception as e:
        raise _explain(e, "read")
