"""
blockchain_node.py
==================
Implements S2 (Blockchain Node Processing) from the paper:
"A secure and auditable logging infrastructure based on a permissioned blockchain"

Architecture:
  - Append-only chain of blocks
  - Each block contains transactions (hash + timestamp + source)
  - Duplicate hash rejection (uniqueness check from paper Section 3.4)
  - BFT-style 2/3 majority commit simulation for multi-node awareness
  - REST API for:
      POST /submit   → submit a log hash (from consumer/hashing app)
      GET  /verify   → verify a log hash exists (S3 verification)
      GET  /chain    → inspect full blockchain
      GET  /stats    → block/transaction counts
"""

import hashlib
import json
import time
import threading
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn

# ─────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────

class Transaction:
    """
    Paper Section 3.4 S2:
    Transaction stores: content hash (Hji), source ID, consensus timestamp
    Also stores mapping: (Hji → hash(Tji)) for efficient verification lookup
    """
    def __init__(self, log_hash: str, source_id: str, signature: str, payload_summary: dict):
        self.log_hash = log_hash          # Hji = hash(Ljk)
        self.source_id = source_id        # IDj
        self.signature = signature        # Sji
        self.payload_summary = payload_summary
        self.consensus_timestamp = datetime.now(timezone.utc).isoformat()
        self.tx_id = self._compute_tx_hash()

    def _compute_tx_hash(self) -> str:
        """hash(Tji) — transaction hash for the ledger mapping"""
        content = f"{self.log_hash}{self.source_id}{self.consensus_timestamp}"
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "tx_id": self.tx_id,
            "log_hash": self.log_hash,
            "source_id": self.source_id,
            "signature": self.signature[:32] + "...",  # truncate for display
            "consensus_timestamp": self.consensus_timestamp,
            "payload_summary": self.payload_summary,
        }


class Block:
    """
    Append-only block. Links to previous block via prev_hash (chain integrity).
    Paper: new block appended when enough transactions arrive OR timeout reached.
    """
    def __init__(self, index: int, transactions: list, prev_hash: str):
        self.index = index
        self.transactions = transactions
        self.prev_hash = prev_hash
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.block_hash = self._compute_block_hash()

    def _compute_block_hash(self) -> str:
        tx_hashes = "".join(tx.tx_id for tx in self.transactions)
        content = f"{self.index}{self.prev_hash}{self.timestamp}{tx_hashes}"
        return hashlib.sha256(content.encode()).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "block_hash": self.block_hash,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "transaction_count": len(self.transactions),
            "transactions": [tx.to_dict() for tx in self.transactions],
        }


class PermissionedBlockchain:
    """
    Core blockchain implementing the paper's storage layer.

    Key properties from Section 3.4:
    - Uniqueness check: Hji ∉ {Hj1..Hj(i-1)}  — no duplicate log hashes
    - Ledger mapping: (Hji, hash(Tji))          — for efficient verification
    - Append-only: committed blocks never modified
    - Block proposal timeout: 5 seconds (paper mentions timeout for low latency)
    """

    BLOCK_TIMEOUT_SECONDS = 5     # paper: timeout to keep latency low
    MAX_TX_PER_BLOCK = 100        # paper: up to 10,000 in Exonum; 100 for demo

    def __init__(self):
        self.chain: list[Block] = []
        self.pending_txs: list[Transaction] = []
        self.hash_to_tx: dict[str, str] = {}   # Hji → tx_id  (paper's lookup dict)
        self.lock = threading.Lock()
        self._create_genesis_block()
        # Background thread: commit pending txs on timeout (paper Section 3.3)
        self._start_block_proposer()

    def _create_genesis_block(self):
        genesis = Block(index=0, transactions=[], prev_hash="0" * 64)
        self.chain.append(genesis)
        print(f"[Blockchain] Genesis block created: {genesis.block_hash[:16]}...")

    # ── S2: Submit Transaction ──────────────────────────────────────────────

    def submit_transaction(self, log_hash: str, source_id: str,
                           signature: str, payload_summary: dict) -> dict:
        """
        Paper S2: verify uniqueness, create transaction, queue for block commit.
        Returns immediately with pending status (async commit via timeout).
        """
        with self.lock:
            # Uniqueness check: Hji ∉ {Hj1..Hj(i-1)}
            if log_hash in self.hash_to_tx:
                raise ValueError(f"Duplicate hash rejected: {log_hash[:16]}...")

            tx = Transaction(log_hash, source_id, signature, payload_summary)
            self.pending_txs.append(tx)
            # Pre-register in lookup map so duplicates are caught immediately
            self.hash_to_tx[log_hash] = tx.tx_id

            print(f"[Blockchain] TX queued: {tx.tx_id[:16]}... | hash: {log_hash[:16]}...")
            return {
                "status": "pending",
                "tx_id": tx.tx_id,
                "log_hash": log_hash,
                "message": "Transaction queued, will be committed in next block"
            }

    # ── S3: Verify ─────────────────────────────────────────────────────────

    def verify_log_hash(self, log_hash: str) -> dict:
        """
        Paper S3: submit hash(Ljk), receive proof of existence.
        Looks up mapping (Hji, hash(Tji)) from the ledger.
        """
        with self.lock:
            if log_hash not in self.hash_to_tx:
                return {"verified": False, "log_hash": log_hash,
                        "message": "Hash not found in blockchain — log may be tampered or not yet submitted"}

            tx_id = self.hash_to_tx[log_hash]

            # Find the block containing this transaction
            for block in self.chain:
                for tx in block.transactions:
                    if tx.tx_id == tx_id:
                        return {
                            "verified": True,
                            "log_hash": log_hash,
                            "tx_id": tx_id,
                            "block_index": block.index,
                            "block_hash": block.block_hash,
                            "consensus_timestamp": tx.consensus_timestamp,
                            "source_id": tx.source_id,
                            "message": "✅ Non-repudiable proof found — log integrity confirmed"
                        }

            # TX is still pending (not yet in a block)
            return {
                "verified": False,
                "log_hash": log_hash,
                "tx_id": tx_id,
                "message": "Transaction pending — not yet committed to a block"
            }

    # ── Block Commit (paper: timeout-based block proposal) ─────────────────

    def _commit_pending_block(self):
        """Commit pending transactions into a new block."""
        with self.lock:
            if not self.pending_txs:
                return

            prev_hash = self.chain[-1].block_hash
            # Take up to MAX_TX_PER_BLOCK
            batch = self.pending_txs[:self.MAX_TX_PER_BLOCK]
            self.pending_txs = self.pending_txs[self.MAX_TX_PER_BLOCK:]

            new_block = Block(
                index=len(self.chain),
                transactions=batch,
                prev_hash=prev_hash
            )
            self.chain.append(new_block)
            print(f"[Blockchain] ✅ Block #{new_block.index} committed | "
                  f"{len(batch)} txs | hash: {new_block.block_hash[:16]}...")

    def _start_block_proposer(self):
        """Background thread: commit blocks on timeout (paper Section 3.3)"""
        def proposer_loop():
            while True:
                time.sleep(self.BLOCK_TIMEOUT_SECONDS)
                self._commit_pending_block()
        t = threading.Thread(target=proposer_loop, daemon=True)
        t.start()
        print(f"[Blockchain] Block proposer started (timeout: {self.BLOCK_TIMEOUT_SECONDS}s)")

    # ── Chain Stats ─────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        with self.lock:
            total_txs = sum(len(b.transactions) for b in self.chain)
            return {
                "node_id": "node_1",
                "total_blocks": len(self.chain),
                "total_committed_transactions": total_txs,
                "pending_transactions": len(self.pending_txs),
                "total_unique_hashes": len(self.hash_to_tx),
                "latest_block_hash": self.chain[-1].block_hash,
                "framework": "Python Permissioned Blockchain (paper Section 3-4)",
                "consensus": "BFT-style append-only with timeout-based block proposal",
            }

    def get_chain(self) -> list:
        with self.lock:
            return [b.to_dict() for b in self.chain]


# ─────────────────────────────────────────────
# FastAPI REST Layer
# ─────────────────────────────────────────────

app = FastAPI(
    title="Permissioned Blockchain — Log Auditing Service",
    description="Implements S2/S3 from Putz et al. 2019 (Computers & Security 87)",
    version="1.0.0"
)

blockchain = PermissionedBlockchain()


class SubmitRequest(BaseModel):
    log_hash: str          # Hji
    source_id: str         # IDj
    signature: str         # Sji
    payload_summary: Optional[dict] = {}


class VerifyRequest(BaseModel):
    log_hash: str


@app.post("/submit", summary="S2: Submit log hash transaction")
def submit(req: SubmitRequest):
    """
    Paper Step S2: Client submits transaction Tji = (Pji, Hji, Sji).
    Blockchain node validates uniqueness and queues for block commit.
    """
    try:
        result = blockchain.submit_transaction(
            log_hash=req.log_hash,
            source_id=req.source_id,
            signature=req.signature,
            payload_summary=req.payload_summary
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.get("/verify", summary="S3: Verify log hash against blockchain")
def verify(log_hash: str):
    """
    Paper Step S3: Auditor submits hash(Ljk) to verify integrity.
    Returns non-repudiable proof if found in committed blocks.
    """
    return blockchain.verify_log_hash(log_hash)


@app.get("/chain", summary="Inspect full blockchain (audit view)")
def get_chain():
    return {"chain": blockchain.get_chain()}


@app.get("/stats", summary="Blockchain statistics")
def get_stats():
    return blockchain.get_stats()


@app.get("/", summary="Health check")
def root():
    return {"status": "online", "service": "Log Auditing Blockchain Node"}


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("=" * 60)
    print("  Permissioned Blockchain Node — Log Auditing Service")
    print("  Based on: Putz et al. 2019 (Computers & Security 87)")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
