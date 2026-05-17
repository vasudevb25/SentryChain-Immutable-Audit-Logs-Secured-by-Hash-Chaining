import json
import hashlib
import requests

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

# =========================================================
# CONFIG
# =========================================================

BLOCKCHAIN_URL = "http://localhost:8000"

# =========================================================
# LOAD PUBLIC KEY
# =========================================================

with open("public.pem", "rb") as f:

    public_key = serialization.load_pem_public_key(
        f.read()
    )

# =========================================================
# COMPUTE HASH
# Must match collector.py EXACTLY
# =========================================================

def compute_hash(payload):

    payload_string = json.dumps(
        payload,
        sort_keys=True
    )

    return hashlib.sha256(
        payload_string.encode()
    ).hexdigest()

# =========================================================
# VERIFY SIGNATURE
# =========================================================

def verify_signature(payload, signature_hex):

    try:

        signature = bytes.fromhex(
            signature_hex
        )

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

    except Exception as e:

        print(
            f"[Auditor] Signature verification failed: {e}"
        )

        return False

# =========================================================
# VERIFY EVIDENCE
# =========================================================

def verify_evidence(evidence):

    print("\n[Auditor] Starting verification")

    try:

        payload = evidence["payload"]

        stored_hash = evidence["hash"]

        signature = evidence["signature"]

        # =================================================
        # STEP 1 — HASH VERIFICATION
        # =================================================

        computed_hash = compute_hash(
            payload
        )

        if computed_hash != stored_hash:

            print(
                "\n[Auditor] HASH MISMATCH"
            )

            print(
                f"Stored   : {stored_hash}"
            )

            print(
                f"Computed : {computed_hash}"
            )

            return

        print("[Auditor] Hash valid")

        # =================================================
        # STEP 2 — SIGNATURE VERIFICATION
        # =================================================

        sig_ok = verify_signature(
            payload,
            signature
        )

        if not sig_ok:

            print(
                "[Auditor] INVALID SIGNATURE"
            )

            return

        print(
            "[Auditor] Signature valid"
        )

        # =================================================
        # STEP 3 — BLOCKCHAIN VERIFICATION
        # =================================================

        response = requests.get(

            f"{BLOCKCHAIN_URL}/verify",

            params={
                "log_hash": stored_hash
            }
        )

        result = response.json()

        if not result.get("verified"):

            print(
                "[Auditor] HASH NOT FOUND ON BLOCKCHAIN"
            )

            return

        print(
            "[Auditor] Blockchain proof valid"
        )

        # =================================================
        # SUCCESS
        # =================================================

        print("\n========== VERIFIED ==========")

        print(
            f"Block Index : "
            f"{result['block_index']}"
        )

        print(
            f"TX ID       : "
            f"{result['tx_id'][:16]}..."
        )

        print(
            f"Block Hash  : "
            f"{result['block_hash'][:16]}..."
        )

        print(
            f"Timestamp   : "
            f"{result['consensus_timestamp']}"
        )

        print("==============================")

    except Exception as e:

        print(
            f"\n[Auditor] Verification error: {e}"
        )

# =========================================================
# TEST FILE
# =========================================================

if __name__ == "__main__":

    try:

        with open(
            "sample_evidence.json"
        ) as f:

            evidence = json.load(f)

        verify_evidence(evidence)

    except FileNotFoundError:

        print(
            "[Auditor] sample_evidence.json not found"
        )

    except Exception as e:

        print(
            f"[Auditor] Fatal error: {e}"
        )