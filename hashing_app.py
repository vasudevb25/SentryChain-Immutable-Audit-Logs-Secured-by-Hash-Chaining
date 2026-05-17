import json
import requests
from kafka import KafkaConsumer

# CONFIG
KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "log_topic"
BLOCKCHAIN_URL = "http://localhost:8000"

# Submit Evidence to Blockchain
def submit_to_blockchain(evidence):
    log_hash = evidence.get("hash")
    if not log_hash:
        print("[HashingApp] No hash found")
        return
    
    payload = evidence.get("payload", {})
    body = {
        "log_hash": log_hash,
        "source_id":
            payload.get(
                "source_id",
                "system_1"
            ),
        # ORIGINAL PRODUCER SIGNATURE
        "signature":
            evidence.get("signature"),
        # Data forwarded to blockchain
        "payload_summary": {
            # REQUIRED FOR VERIFICATION
            "original_payload":
                payload,
            "public_key":
                payload.get("public_key"),
            # Metadata
            "source_id":
                payload.get("source_id"),
            "ingest_timestamp":
                evidence.get("ingest_timestamp"),
            "source_ip":
                evidence.get("source_ip"),
            "log_process":
                payload.get("log", {})
                .get("process", "unknown")
        }
    }

    try:
        response = requests.post(
            f"{BLOCKCHAIN_URL}/submit",
            json=body,
            timeout=5
        )
        if response.status_code == 200:
            result = response.json()
            print(
                f"[HashingApp] "
                f"TX submitted "
                f"| tx_id: {result['tx_id'][:16]}... "
                f"| hash: {log_hash[:16]}..."
            )
        # DUPLICATE
        elif response.status_code == 409:
            print(
                f"[HashingApp] "
                f"Duplicate rejected "
                f"| hash: {log_hash[:16]}..."
            )
        # BLOCKCHAIN ERROR
        else:
            print(
                f"[HashingApp] "
                f"Blockchain error: "
                f"{response.text}"
            )

    except requests.exceptions.ConnectionError:
        print(
            "[HashingApp] "
            "Cannot connect to blockchain node"
        )

    except Exception as e:
        print(
            f"[HashingApp] Error: {e}"
        )


# MAIN LOOP
def run():
    print("=" * 60)
    print(" Hashing Application")
    print(" Kafka -> Permissioned Blockchain")
    print("=" * 60)
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_deserializer=lambda m:
            json.loads(m.decode()),
        auto_offset_reset="earliest",
        group_id="hashing_app_group"
    )
    print(
        "[HashingApp] Listening for Kafka events..."
    )
    for message in consumer:
        evidence = message.value
        log_hash = evidence.get("hash", "")
        print(
            f"\n[HashingApp] "
            f"Received hash: "
            f"{log_hash[:16]}..."
        )
        submit_to_blockchain(evidence)


# ENTRY POINT
if __name__ == "__main__":
    try:
        run()
    except KeyboardInterrupt:
        print(
            "\n[HashingApp] Shutdown requested"
        )
    except Exception as e:
        print(
            f"\n[HashingApp] Fatal error: {e}"
        )
    finally:
        print(
            "[HashingApp] Stopped cleanly"
        )