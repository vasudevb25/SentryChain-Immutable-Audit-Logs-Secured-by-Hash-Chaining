"""
auditor.py
==========
Paper Step S3 — Dispute Resolution / Verification

"To verify, a user may optionally submit a log entry to the client application,
which requests a proof from the blockchain network by sending hash(Ljk).
If the corresponding transaction is found and returned, only its signature
and hash must be verified."

  verify(Kj, Pji, Sji) ∧ Kj ∈ {K1..Kn} ∧ Hji == hash(Ljk)

Usage:
  python auditor.py --hash <log_hash>
  python auditor.py --file <evidence_json_file>
  python auditor.py --stats
  python auditor.py --chain
"""

import argparse
import json
import hashlib
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

BLOCKCHAIN_URL = "http://localhost:8000"


# ─────────────────────────────────────────────
# Signature Verification (S3)
# ─────────────────────────────────────────────

def verify_signature(evidence: dict) -> bool:
    """
    Paper S3: verify(Kj, Pji, Sji)
    Checks that the payload was signed by the claimed source's private key.
    """
    try:
        public_key_pem = evidence["payload"]["public_key"].encode()
        public_key = serialization.load_pem_public_key(public_key_pem)

        payload_string = json.dumps(evidence["payload"], sort_keys=True)
        signature_bytes = bytes.fromhex(evidence["signature"])

        public_key.verify(
            signature_bytes,
            payload_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"  [!] Signature check error: {e}")
        return False


def recompute_hash(evidence: dict) -> str:
    """Recompute hash(Ljk) from evidence payload to confirm Hji == hash(Ljk)"""
    payload_string = json.dumps(evidence["payload"], sort_keys=True)
    return hashlib.sha256(payload_string.encode()).hexdigest()


# ─────────────────────────────────────────────
# Blockchain Proof Lookup
# ─────────────────────────────────────────────

def query_blockchain(log_hash: str) -> dict:
    try:
        response = requests.get(f"{BLOCKCHAIN_URL}/verify", params={"log_hash": log_hash}, timeout=5)
        return response.json()
    except requests.exceptions.ConnectionError:
        return {"verified": False, "message": "Cannot connect to blockchain node"}


# ─────────────────────────────────────────────
# Full S3 Verification Flow
# ─────────────────────────────────────────────

def full_verify(evidence: dict):
    """
    Complete S3 verification as per paper:
    1. Verify signature against public key (authenticity)
    2. Recompute hash and compare (integrity)
    3. Query blockchain for non-repudiable proof (immutability)
    """
    print("\n" + "=" * 58)
    print("  AUDITOR — S3 Verification (Putz et al. 2019)")
    print("=" * 58)

    log_hash = evidence.get("hash")
    source = evidence.get("payload", {}).get("source_id", "unknown")
    timestamp = evidence.get("ingest_timestamp", "unknown")

    print(f"\n  Source ID  : {source}")
    print(f"  Timestamp  : {timestamp}")
    print(f"  Hash       : {log_hash[:32]}...")

    # Step 1: Signature check
    print("\n  [1] Signature Verification...")
    sig_valid = verify_signature(evidence)
    print(f"      {'✅ VALID — payload authenticated to source' if sig_valid else '❌ INVALID — signature mismatch!'}")

    # Step 2: Hash integrity
    print("\n  [2] Hash Integrity Check...")
    computed = recompute_hash(evidence)
    hash_match = computed == log_hash
    print(f"      Stored hash  : {log_hash[:32]}...")
    print(f"      Computed hash: {computed[:32]}...")
    print(f"      {'✅ MATCH — evidence data unmodified' if hash_match else '❌ MISMATCH — data may have been tampered!'}")

    # Step 3: Blockchain proof
    print("\n  [3] Blockchain Proof Lookup...")
    proof = query_blockchain(log_hash)
    bc_verified = proof.get("verified", False)
    if bc_verified:
        print(f"      ✅ FOUND in blockchain")
        print(f"      Block #    : {proof.get('block_index')}")
        print(f"      Block hash : {proof.get('block_hash', '')[:32]}...")
        print(f"      TX commit  : {proof.get('consensus_timestamp')}")
    else:
        print(f"      ❌ NOT FOUND: {proof.get('message')}")

    # Final verdict
    print("\n" + "─" * 58)
    if sig_valid and hash_match and bc_verified:
        print("  ✅ VERDICT: LOG ENTRY IS AUTHENTIC AND UNMODIFIED")
        print("     Non-repudiable proof confirmed in blockchain.")
    else:
        print("  ❌ VERDICT: VERIFICATION FAILED")
        failures = []
        if not sig_valid:   failures.append("invalid signature")
        if not hash_match:  failures.append("hash mismatch")
        if not bc_verified: failures.append("not found in blockchain")
        print(f"     Reasons: {', '.join(failures)}")
    print("=" * 58 + "\n")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Auditor — Log Verification Tool (Paper S3)")
    parser.add_argument("--hash", help="Verify a specific log hash against the blockchain")
    parser.add_argument("--file", help="Verify a full evidence JSON file (complete S3 check)")
    parser.add_argument("--stats", action="store_true", help="Show blockchain statistics")
    parser.add_argument("--chain", action="store_true", help="Show full blockchain")
    args = parser.parse_args()

    if args.stats:
        r = requests.get(f"{BLOCKCHAIN_URL}/stats")
        print(json.dumps(r.json(), indent=2))

    elif args.chain:
        r = requests.get(f"{BLOCKCHAIN_URL}/chain")
        data = r.json()
        for block in data["chain"]:
            print(f"\nBlock #{block['index']} | {block['timestamp']}")
            print(f"  Hash    : {block['block_hash'][:32]}...")
            print(f"  PrevHash: {block['prev_hash'][:32]}...")
            print(f"  TXs     : {block['transaction_count']}")

    elif args.hash:
        proof = query_blockchain(args.hash)
        print(json.dumps(proof, indent=2))

    elif args.file:
        with open(args.file) as f:
            evidence = json.load(f)
        full_verify(evidence)

    else:
        # Interactive demo mode
        print("\n[Auditor] No arguments given. Fetching stats from blockchain...\n")
        try:
            r = requests.get(f"{BLOCKCHAIN_URL}/stats")
            print(json.dumps(r.json(), indent=2))
            print("\nUsage:")
            print("  python auditor.py --hash <sha256_hash>")
            print("  python auditor.py --file evidence.json")
            print("  python auditor.py --stats")
            print("  python auditor.py --chain")
        except Exception:
            print("Could not connect to blockchain node at", BLOCKCHAIN_URL)


if __name__ == "__main__":
    main()
