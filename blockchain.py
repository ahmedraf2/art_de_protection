"""
A minimal, self-contained blockchain used as a tamper-evident integrity ledger.

Each block is SHA-256-linked to the one before it:

    hash = SHA256( index | timestamp | data | prev_hash | nonce )

Because every block commits to the previous block's hash, editing the data in
any block changes that block's hash and breaks the link to the next one, so
verify_chain() can detect exactly where a record was altered. A small
proof-of-work (a few leading zero hex digits) is required for each block, the
same mechanism real chains use to make history expensive to rewrite.

The chain is stored in the 'blockchain' table of the same per-build database.
This is a teaching implementation — no external service, runs entirely offline —
but the cryptography (hashing, linking, proof-of-work, verification) is real.
"""

import json
import time
import hashlib

DIFFICULTY = 3                      # required leading zero hex digits in a hash
GENESIS_PREV = "0" * 64


def _canon(data) -> str:
    """Canonical JSON for a record, so the same data always hashes the same."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _hash(index, timestamp, data_str, prev_hash, nonce) -> str:
    msg = f"{index}\n{timestamp}\n{data_str}\n{prev_hash}\n{nonce}".encode()
    return hashlib.sha256(msg).hexdigest()


def _mine(index, timestamp, data_str, prev_hash):
    """Find a nonce whose block hash starts with DIFFICULTY zeros (proof-of-work)."""
    prefix = "0" * DIFFICULTY
    nonce = 0
    while True:
        h = _hash(index, timestamp, data_str, prev_hash, nonce)
        if h.startswith(prefix):
            return nonce, h
        nonce += 1


# --- persistence ---------------------------------------------------------
def _all_rows(conn):
    cur = conn.execute("SELECT idx, timestamp, data, prev_hash, nonce, hash "
                       "FROM blockchain ORDER BY idx")
    return [dict(r) for r in cur.fetchall()]


def height(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM blockchain").fetchone()[0]


def last_hash(conn):
    row = conn.execute("SELECT hash FROM blockchain ORDER BY idx DESC LIMIT 1").fetchone()
    return row[0] if row else None


def ensure_genesis(conn, commit=True):
    if height(conn) == 0:
        add_block(conn, {"type": "genesis", "note": "Campus integrity ledger"}, commit=commit)


def add_block(conn, data, commit=True) -> str:
    """Append a record to the chain and return the new block's hash."""
    idx = height(conn)
    prev = last_hash(conn) or GENESIS_PREV
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    data_str = _canon(data)
    nonce, h = _mine(idx, ts, data_str, prev)
    conn.execute("INSERT INTO blockchain (idx, timestamp, data, prev_hash, nonce, hash) "
                 "VALUES (?,?,?,?,?,?)", (idx, ts, data_str, prev, nonce, h))
    if commit:
        conn.commit()
    return h


# --- verification + lookup ----------------------------------------------
def verify_chain(conn):
    """Recompute every hash and check every link. Returns (ok, [problems])."""
    rows = _all_rows(conn)
    problems = []
    prev = GENESIS_PREV
    prefix = "0" * DIFFICULTY
    for i, b in enumerate(rows):
        if b["idx"] != i:
            problems.append({"idx": b["idx"], "error": "unexpected block index"})
        if b["prev_hash"] != prev:
            problems.append({"idx": b["idx"], "error": "broken link to previous block"})
        recomputed = _hash(b["idx"], b["timestamp"], b["data"], b["prev_hash"], b["nonce"])
        if recomputed != b["hash"]:
            problems.append({"idx": b["idx"], "error": "hash mismatch — data was altered"})
        if not b["hash"].startswith(prefix):
            problems.append({"idx": b["idx"], "error": "invalid proof-of-work"})
        prev = b["hash"]
    return (len(problems) == 0, problems)


def blocks(conn):
    """All blocks with their data parsed back into dicts (for the explorer)."""
    out = []
    for b in _all_rows(conn):
        rec = dict(b)
        try:
            rec["data"] = json.loads(b["data"])
        except Exception:
            rec["data"] = {}
        out.append(rec)
    return out


def find(conn, **match):
    """Blocks whose parsed data matches every given field (latest last)."""
    res = []
    for b in blocks(conn):
        d = b.get("data") or {}
        if all(d.get(k) == v for k, v in match.items()):
            res.append(b)
    return res
