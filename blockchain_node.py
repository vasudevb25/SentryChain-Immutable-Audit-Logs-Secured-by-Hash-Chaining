import hashlib
import json
import time
import threading
import argparse
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from fastapi.middleware.cors import CORSMiddleware

import time
# MERKLE TREE
def compute_merkle_root(tx_ids):
    hashes_list = tx_ids[:]
    if not hashes_list:
        return hashlib.sha256(b"empty").hexdigest()
    while len(hashes_list) > 1:
        if len(hashes_list) % 2 == 1:
            hashes_list.append(hashes_list[-1])
        new_level = []
        for i in range(0, len(hashes_list), 2):
            combined = hashes_list[i] + hashes_list[i + 1]
            new_hash = hashlib.sha256(
                combined.encode()
            ).hexdigest()
            new_level.append(new_hash)
        hashes_list = new_level
    return hashes_list[0]

# TRANSACTION
class Transaction:
    def __init__(
        self,
        log_hash,
        source_id,
        signature,
        payload_summary
    ):
        self.log_hash = log_hash
        self.source_id = source_id
        self.signature = signature
        self.payload_summary = payload_summary
        self.consensus_timestamp = datetime.now(
            timezone.utc
        ).isoformat()
        self.tx_id = self.compute_tx_hash()

    def compute_tx_hash(self):
        content = (
            f"{self.log_hash}"
            f"{self.source_id}"
            f"{self.consensus_timestamp}"
        )
        return hashlib.sha256(
            content.encode()
        ).hexdigest()

    def to_dict(self):
        return {
            "tx_id": self.tx_id,
            "log_hash": self.log_hash,
            "source_id": self.source_id,
            "signature":
                self.signature,
            "consensus_timestamp":
                self.consensus_timestamp,
            "payload_summary":
                self.payload_summary
        }


# BLOCK   
class Block:
    def __init__(
        self,
        index,
        transactions,
        prev_hash
    ):
        self.index = index
        self.transactions = transactions
        self.prev_hash = prev_hash
        self.timestamp = datetime.now(
            timezone.utc
        ).isoformat()
        self.merkle_root = compute_merkle_root(
            [tx.tx_id for tx in transactions]
        )
        self.block_hash = self.compute_block_hash()

    def compute_block_hash(self):
        content = (
            f"{self.index}"
            f"{self.prev_hash}"
            f"{self.timestamp}"
            f"{self.merkle_root}"
        )
        return hashlib.sha256(
            content.encode()
        ).hexdigest()
    
    def validate_block(self):
        return (
            self.compute_block_hash()
            == self.block_hash
        )

    def to_dict(self):
        return {
            "index": self.index,
            "block_hash": self.block_hash,
            "prev_hash": self.prev_hash,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "transaction_count": len(self.transactions),
            "transactions": [tx.to_dict() for tx in self.transactions]   
        }

# BLOCKCHAIN
class PermissionedBlockchain:
    BLOCK_TIMEOUT_SECONDS = 2
    MAX_TX_PER_BLOCK = 5

    def __init__(self):
        self.chain = []
        self.pending_txs = []
        self.hash_to_tx = {}
        self.lock = threading.Lock()
        self.storage_file = "blockchain_data.json"
        self.load_chain()
        self.start_block_proposer()

    def create_genesis_block(self):
        genesis = Block(
            index=0,
            transactions=[],
            prev_hash="0" * 64
        )
        self.chain.append(genesis)
        print(
            f"[Blockchain] Genesis block created: "
            f"{genesis.block_hash[:16]}..."
        )

    def verify_signature(
        self,
        public_key_pem,
        signature_hex,
        payload
    ):
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
            signature = bytes.fromhex(signature_hex)
            public_key.verify(
                signature,
                json.dumps(
                    payload,
                    sort_keys=True
                ).encode(),
                padding.PSS(
                    mgf=padding.MGF1(
                        hashes.SHA256()
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True

        except Exception:
            return False

    def submit_transaction(
        self,
        log_hash,
        source_id,
        signature,
        payload_summary
    ):
        payload = payload_summary.get(
            "original_payload"
        )
        public_key = payload_summary.get(
            "public_key"
        )
        valid_signature = self.verify_signature(
            public_key,
            signature,
            payload
        )
        if not valid_signature:
            raise ValueError(
                "Invalid digital signature"
            )
        with self.lock:
            if log_hash in self.hash_to_tx:
                raise ValueError(
                    f"Duplicate hash rejected: "
                    f"{log_hash[:16]}..."
                )
            tx = Transaction(
                log_hash,
                source_id,
                signature,
                payload_summary
            )
            self.pending_txs.append(tx)
            self.hash_to_tx[
                log_hash
            ] = tx.tx_id
            print(
                f"[Blockchain] TX queued: "
                f"{tx.tx_id[:16]}..."
            )

            return {
                "status": "pending",
                "tx_id": tx.tx_id,
                "message":
                    "Transaction queued"
            }

    def commit_pending_block(self):
        with self.lock:
            if not self.pending_txs:
                return
            prev_hash = self.chain[-1].block_hash
            batch = self.pending_txs[
                :self.MAX_TX_PER_BLOCK
            ]
            self.pending_txs = self.pending_txs[
                self.MAX_TX_PER_BLOCK:
            ]

            block = Block(
                index=len(self.chain),
                transactions=batch,
                prev_hash=prev_hash
            )

            self.chain.append(block)
            self.save_chain()

            print(
                f"[Blockchain] "
                f"Block #{block.index} committed "
                f"| {len(batch)} txs"
            )

    def start_block_proposer(self):
        def proposer_loop():
            while True:
                time.sleep(
                    self.BLOCK_TIMEOUT_SECONDS
                )
                self.commit_pending_block()

        thread = threading.Thread(
            target=proposer_loop,
            daemon=True
        )

        thread.start()

    def verify_log_hash(self, log_hash):
        with self.lock:
            if log_hash not in self.hash_to_tx:
                return {
                    "verified": False,
                    "message":
                        "Hash not found"
                }
            tx_id = self.hash_to_tx[log_hash]

            for block in self.chain:
                for tx in block.transactions:
                    if tx.tx_id == tx_id:
                        return {
                            "verified": True,
                            "tx_id": tx.tx_id,
                            "block_index":
                                block.index,
                            "block_hash":
                                block.block_hash,
                            "source_id":
                                tx.source_id,
                            "timestamp":
                                tx.consensus_timestamp
                        }
            return {
                "verified": False,
                "message":
                    "Transaction pending"
            }

    def validate_chain(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.prev_hash != previous.block_hash:
                return False
            if not current.validate_block():
                return False
        return True

    def save_chain(self):
        data = [
            block.to_dict()
            for block in self.chain
        ]
        with open(
            self.storage_file,
            "w"
        ) as f:
            json.dump(
                data,
                f,
                indent=4
            )

    def load_chain(self):
        try:
            with open(
                self.storage_file,
                "r"
            ) as f:
                data = json.load(f)

            for block_data in data:
                txs = []
                for tx_data in block_data["transactions"]:
                    tx = Transaction(
                        tx_data["log_hash"],
                        tx_data["source_id"],
                        tx_data["signature"],
                        tx_data["payload_summary"]
                    )
                    tx.tx_id = tx_data["tx_id"]
                    tx.consensus_timestamp = tx_data[
                        "consensus_timestamp"
                    ]
                    txs.append(tx)
                    self.hash_to_tx[
                        tx.log_hash
                    ] = tx.tx_id

                block = Block(
                    block_data["index"],
                    txs,
                    block_data["prev_hash"]
                )

                block.timestamp = block_data["timestamp"]
                block.block_hash = block_data[
                    "block_hash"
                ]

                block.merkle_root = block_data[
                    "merkle_root"
                ]

                self.chain.append(block)

            print(
                "[Blockchain] Chain restored"
            )

        except FileNotFoundError:
            self.create_genesis_block()

    def get_chain(self):
        return [
            block.to_dict()
            for block in self.chain
        ]

    def get_stats(self):
        total_txs = sum(
            len(b.transactions)
            for b in self.chain
        )
        return {
            "total_blocks": len(self.chain),
            "total_committed_transactions": total_txs,
            "pending_transactions": len(self.pending_txs),
            "total_unique_hashes": len(self.hash_to_tx),
            "latest_block_hash": self.chain[-1].block_hash
        }

# FastAPI
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
blockchain = PermissionedBlockchain()

# =========================================================
# TPS METRICS
# =========================================================

START_TIME = time.time()

TOTAL_TRANSACTIONS = 0

# Models
class SubmitRequest(BaseModel):
    log_hash: str
    source_id: str
    signature: str
    payload_summary: Optional[dict] = {}
class AuditRequest(BaseModel):
    evidence: dict
class VerifyRequest(BaseModel):
    evidence: dict


@app.post("/submit")
def submit(req: SubmitRequest):
    try:
        global TOTAL_TRANSACTIONS
        # existing validation logic...
        TOTAL_TRANSACTIONS += 1
        elapsed_time = time.time() - START_TIME
        tps = TOTAL_TRANSACTIONS / elapsed_time
        print(
            f"[Blockchain] TPS: {tps:.2f} | "
            f"Total TX: {TOTAL_TRANSACTIONS}"
        )
        return blockchain.submit_transaction(
            req.log_hash,
            req.source_id,
            req.signature,
            req.payload_summary
        )

    except ValueError as e:
        raise HTTPException(
            status_code=409,
            detail=str(e)
        )

@app.get("/verify")
def verify(log_hash: str):
    return blockchain.verify_log_hash(
        log_hash
    )

@app.get("/chain")
def get_chain():
    return {
        "chain":
            blockchain.get_chain()
    }

@app.get("/stats")
def get_stats():
    return blockchain.get_stats()

@app.get("/validate")
def validate():
    return {
        "chain_valid":
            blockchain.validate_chain(),
        "total_blocks":
            len(blockchain.chain)
    }

@app.get("/")
def root():
    return {
        "status": "online",
        "service":
            "Permissioned Blockchain"
    }

# MAIN
@app.post("/audit/verify")
def audit_verify(req: AuditRequest):
    evidence = req.evidence
    try:
        payload = evidence["payload"]
        stored_hash = evidence["hash"]
        signature_hex = evidence["signature"]

        # Recompute SHA256
        computed_hash = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True
            ).encode()

        ).hexdigest()

        if computed_hash != stored_hash:
            return {
                "verified": False,
                "reason": "HASH_MISMATCH"
            }
        
        # Verify RSA Signature
        public_key_pem = payload["public_key"]
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode()
        )
        signature = bytes.fromhex(signature_hex)
        public_key.verify(
            signature,
            json.dumps(
                payload,
                sort_keys=True
            ).encode(),
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Blockchain Lookup
        result = blockchain.verify_log_hash(
            stored_hash
        )
        if not result["verified"]:
            return {
                "verified": False,
                "reason": "NOT_FOUND_ON_CHAIN"
            }
        return {
            "verified": True,
            "block_index":
                result["block_index"],
            "tx_id":
                result["tx_id"],
            "block_hash":
                result["block_hash"],
            "message":
                "Evidence verified successfully"
        }

    except Exception as e:
        return {
            "verified": False,
            "reason": str(e)
        }


if __name__ == "__main__":
    print("=" * 60)
    print(
        " Permissioned Blockchain Node"
    )
    print("=" * 60)
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--port",
        type=int,
        default=8000
    )

    args = parser.parse_args()
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=args.port,
        log_level="warning"
    )