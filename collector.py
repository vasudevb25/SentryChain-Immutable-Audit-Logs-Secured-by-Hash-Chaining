import socket
import json
import re
import hashlib
from datetime import datetime
from kafka import KafkaProducer

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# =========================
# Kafka Setup
# =========================
producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

# =========================
# Load Keys
# =========================
with open("private.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None
    )

with open("public.pem", "rb") as f:
    public_key_bytes = f.read().decode()

# =========================
# Sign Function
# =========================
def sign_data(data):
    return private_key.sign(
        data.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ).hex()

# =========================
# Syslog Parser
# =========================
def parse_syslog(log):
    pattern = r"<(\d+)>(\w+\s+\d+\s+\d+:\d+:\d+)\s+([\w\-.]+)\s+([\w\-.\/\[\]]+):\s+(.*)"
    
    match = re.match(pattern, log)
    
    if not match:
        return {"raw": log}

    priority, timestamp, host, process, message = match.groups()

    current_year = datetime.now().year
    full_timestamp = f"{timestamp} {current_year}"

    try:
        parsed_time = datetime.strptime(full_timestamp, "%b %d %H:%M:%S %Y")
        parsed_time = parsed_time.isoformat()
    except:
        parsed_time = None

    return {
        "priority": int(priority),
        "timestamp": parsed_time,
        "host": host,
        "process": process,
        "message": message
    }

# =========================
# UDP Setup
# =========================
UDP_IP = "127.0.0.1"
UDP_PORT = 5514

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"[Collector] Listening on {UDP_IP}:{UDP_PORT}")

# =========================
# Main Loop
# =========================
while True:
    data, addr = sock.recvfrom(4096)

    raw_data = data.decode().strip()
    log = parse_syslog(raw_data)

    # Step 1: Create payload (paper: Pji)
    payload = {
        "log": log,
        "source_id": "system_1",
        "public_key": public_key_bytes
    }

    payload_string = json.dumps(payload, sort_keys=True)

    # Step 2: Hash (Hji)
    log_hash = hashlib.sha256(payload_string.encode()).hexdigest()

    # Step 3: Sign (Sji)
    signature = sign_data(payload_string)

    # Step 4: Final Evidence Structure
    evidence = {
        "payload": payload,
        "hash": log_hash,
        "signature": signature,
        "ingest_timestamp": datetime.utcnow().isoformat(),
        "source_ip": addr[0]
    }

    print("[Collector] Evidence:", evidence)

    # Step 5: Send to Kafka
    try:
        producer.send("log_topic", evidence)
        producer.flush()
    except Exception as e:
        print("Kafka error:", e)