"""
hashing_app.py
==============
Paper Figure 4: "A hashing application fetches log records from the data stream
and computes the SHA256 hash for each record. The hash is then submitted to the
blockchain system in a signed transaction."

This is the BRIDGE between Kafka (off-chain storage) and the blockchain node.
Sits between consumer.py and blockchain_node.py in the pipeline.

Pipeline:
  Kafka (log_topic)  →  hashing_app.py  →  blockchain_node.py (POST /submit)
"""

import json
import requests
import hashlib
from kafka import KafkaConsumer
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# ─────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────

KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "log_topic"
BLOCKCHAIN_URL = "http://localhost:8000"
SOURCE_ID = "system_1"

# ─────────────────────────────────────────────
# Load signing key (same keypair as collector)
# ─────────────────────────────────────────────

with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(f.read(), password=None)


def sign_hash(log_hash: str) -> str:
    """Sign the hash before submitting to blockchain (proves source authenticity)"""
    return private_key.sign(
        log_hash.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ).hex()


# ─────────────────────────────────────────────
# Submit to Blockchain Node
# ─────────────────────────────────────────────

def submit_to_blockchain(evidence: dict) -> bool:
    """
    Paper Fig 4: 'The hash is then submitted to the blockchain system
    in a signed transaction.'
    """
    log_hash = evidence.get("hash")
    if not log_hash:
        print("[HashingApp] ❌ No hash in evidence, skipping")
        return False

    signature = sign_hash(log_hash)

    # Compact payload summary for on-chain storage (paper: only hash stored on-chain)
    payload_summary = {
        "source_id": evidence.get("payload", {}).get("source_id", SOURCE_ID),
        "ingest_timestamp": evidence.get("ingest_timestamp"),
        "source_ip": evidence.get("source_ip"),
        "log_process": evidence.get("payload", {}).get("log", {}).get("process", "unknown"),
    }

    body = {
        "log_hash": log_hash,
        "source_id": SOURCE_ID,
        "signature": signature,
        "payload_summary": payload_summary
    }

    try:
        response = requests.post(f"{BLOCKCHAIN_URL}/submit", json=body, timeout=5)
        if response.status_code == 200:
            result = response.json()
            print(f"[HashingApp] ✅ TX submitted | tx_id: {result['tx_id'][:16]}... | hash: {log_hash[:16]}...")
            return True
        elif response.status_code == 409:
            print(f"[HashingApp] ⚠️  Duplicate rejected by blockchain: {log_hash[:16]}...")
            return False
        else:
            print(f"[HashingApp] ❌ Blockchain error {response.status_code}: {response.text}")
            return False
    except requests.exceptions.ConnectionError:
        print("[HashingApp] ❌ Cannot connect to blockchain node — is blockchain_node.py running?")
        return False
    except Exception as e:
        print(f"[HashingApp] ❌ Error: {e}")
        return False


# ─────────────────────────────────────────────
# Kafka Consumer Loop
# ─────────────────────────────────────────────

def run():
    print("=" * 55)
    print("  Hashing App — Log Auditing Layer Bridge")
    print("  Kafka → SHA256 Hash → Blockchain Node")
    print("=" * 55)
    print(f"[HashingApp] Connecting to Kafka: {KAFKA_BOOTSTRAP}")
    print(f"[HashingApp] Blockchain node: {BLOCKCHAIN_URL}")
    print()

    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="earliest",
        group_id="hashing_app_group"
    )

    print(f"[HashingApp] Listening on Kafka topic: {KAFKA_TOPIC}")

    for message in consumer:
        evidence = message.value
        log_hash = evidence.get("hash", "N/A")
        print(f"\n[HashingApp] Received from Kafka | hash: {log_hash[:16]}...")
        submit_to_blockchain(evidence)


if __name__ == "__main__":
    run()
