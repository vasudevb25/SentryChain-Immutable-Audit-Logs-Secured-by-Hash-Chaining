import socket
import json
import re
import hashlib
from datetime import datetime
from kafka import KafkaProducer
from cryptography.hazmat.primitives import (
    serialization,
    hashes
)
from cryptography.hazmat.primitives.asymmetric import (
    padding
)

# CONFIG
UDP_IP = "0.0.0.0"
UDP_PORT = 5514

KAFKA_BOOTSTRAP = "localhost:9092"
KAFKA_TOPIC = "log_topic"

SOURCE_ID = "system_1"

# KAFKA SETUP
producer = KafkaProducer(
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_serializer=lambda v:
        json.dumps(v).encode("utf-8")
)


# LOAD RSA KEYS
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )
with open("public.pem", "rb") as f:
    public_key_bytes = f.read().decode()

# SIGN DATA
def sign_data(data):
    return private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(
                hashes.SHA256()
            ),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ).hex()

# PARSE LINUX SYSLOG
def parse_linux_syslog(log):
    pattern = (
        r"<(\d+)>"
        r"(\w+\s+\d+\s+\d+:\d+:\d+)\s+"
        r"([\w\-.]+)\s+"
        r"([\w\-.\/\[\]]+):\s+"
        r"(.*)"
    )
    match = re.match(pattern, log)
    if not match:
        return None

    priority, timestamp, host, process, message = match.groups()
    current_year = datetime.now().year
    full_timestamp = f"{timestamp} {current_year}"
    try:
        parsed_time = datetime.strptime(
            full_timestamp,
            "%b %d %H:%M:%S %Y"
        ).isoformat()
    except Exception:
        parsed_time = None

    return {
        "platform": "linux",
        "priority": int(priority),
        "timestamp": parsed_time,
        "host": host,
        "process": process,
        "message": message
    }

# PARSE WINDOWS EVENT LOG - (EXPECTS JSON FORWARDED EVENTS)
def parse_windows_log(log):
    try:
        data = json.loads(log)
        if data.get("platform") != "windows":
            return None
        return {
            "platform": "windows",
            "event_id":
                data.get("event_id"),
            "timestamp":
                data.get("timestamp"),
            "host":
                data.get("host"),
            "source":
                data.get("source"),
            "level":
                data.get("level"),
            "message":
                data.get("message")
        }
    except Exception:
        return None

# GENERIC JSON APPLICATION LOG
def parse_json_log(log):
    try:
        data = json.loads(log)
        return {
            "platform":
                data.get("platform", "generic"),
            "timestamp":
                data.get(
                    "timestamp",
                    datetime.utcnow().isoformat()
                ),
            "application":
                data.get("application"),
            "level":
                data.get("level"),
            "message":
                data.get("message"),
            "metadata":
                data.get("metadata", {})
        }
    except Exception:
        return None



# UNIVERSAL PARSER
def parse_log(raw_data):
    # Linux syslog
    linux_log = parse_linux_syslog(raw_data)
    if linux_log:
        return linux_log
    
    # Windows JSON
    windows_log = parse_windows_log(raw_data)
    if windows_log:
        return windows_log

    # Generic JSON app log
    generic_log = parse_json_log(raw_data)
    if generic_log:
        return generic_log

    # Fallback
    return {
        "platform": "unknown",
        "raw": raw_data
    }

# UDP SOCKET
sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM
)

sock.bind((UDP_IP, UDP_PORT))

print(
    f"[Collector] Listening on "
    f"{UDP_IP}:{UDP_PORT}"
)

# MAIN LOOP
while True:
    data, addr = sock.recvfrom(65535)
    raw_data = data.decode(
        errors="ignore"
    ).strip()

    parsed_log = parse_log(raw_data)

    # CREATE PAYLOAD
    payload = {
        "log": parsed_log,
        "source_id": SOURCE_ID,
        "public_key": public_key_bytes
    }

    # SERIALIZE PAYLOAD
    payload_string = json.dumps(
        payload,
        sort_keys=True
    )

    # SHA256 HASH
    log_hash = hashlib.sha256(
        payload_string.encode()
    ).hexdigest()

    # DIGITAL SIGNATURE
    signature = sign_data(
        payload_string
    )

    # EVIDENCE OBJECT
    evidence = {
        "payload": payload,
        "hash": log_hash,
        "signature": signature,
        "ingest_timestamp":
            datetime.utcnow().isoformat(),
        "source_ip":
            addr[0]
    }

    # SAVE SAMPLE EVIDENCE
    with open(
        "sample_evidence.json",
        "w"
    ) as f:
        json.dump(
            evidence,
            f,
            indent=4
        )

    # DISPLAY
    print("\n[Collector] Evidence Received")
    print(
        json.dumps(
            evidence,
            indent=2
        )
    )

    # SEND TO KAFKA
    try:
        producer.send(
            KAFKA_TOPIC,
            evidence
        )
        producer.flush()
    except Exception as e:
        print(
            f"[Collector] Kafka error: {e}"
        )