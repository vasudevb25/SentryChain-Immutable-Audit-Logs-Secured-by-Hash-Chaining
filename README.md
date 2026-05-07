# Tamper-Evident Log Management System

### Phase 1 & Phase 2 Implementation

---

## Overview

This project implements a **secure, tamper-evident logging system** based on a research-driven architecture.

It collects **real-time system logs**, processes them, and converts each log into **cryptographically verifiable evidence** using hashing and digital signatures.

---

## Objectives

- Collect **real system logs** (Linux / syslog)
- Ensure **integrity** using SHA-256 hashing
- Provide **authenticity & non-repudiation** using RSA signatures
- Store logs reliably using Kafka
- Prepare data for **blockchain anchoring (Phase 3)**

---

## End-to-End Pipeline

```text
System Logs (Linux)
        ↓
rsyslog (Forwarding)
        ↓
UDP Transport (Port 5514)
        ↓
Collector (Python)
        ↓
Parse → Structure → Hash → Sign
        ↓
Kafka (log_topic)
        ↓
Consumer (Storage / Retrieval)
```

---

## Technologies Used

| Component    | Technology            |
| ------------ | --------------------- |
| Log Source   | Linux System Logs     |
| Forwarding   | rsyslog               |
| Transport    | UDP (Syslog Protocol) |
| Processing   | Python                |
| Queue System | Apache Kafka          |
| Cryptography | SHA-256, RSA          |

---

## Phase 1: Log Collection

### Features

- Real-time log capture using `rsyslog`
- UDP-based log forwarding
- Syslog parsing into structured JSON
- Kafka-based ingestion pipeline

### Flow

1. System generates logs (`/var/log`, services, `logger`)
2. `rsyslog` forwards logs to `127.0.0.1:5514`
3. Collector receives logs via UDP
4. Logs are parsed into structured format
5. Data is pushed to Kafka

---

## Phase 2: Secure Evidence Generation

Each log is transformed into **tamper-evident evidence**.

### Process

```text
Structured Log
      ↓
SHA-256 Hash
      ↓
Digital Signature (RSA)
      ↓
Evidence Object
```

---

## Evidence Structure

```json
{
  "payload": {
    "log": {
      "priority": 13,
      "timestamp": "2026-05-01T21:30:00",
      "host": "system",
      "process": "cron",
      "message": "example log"
    },
    "source_id": "system_1",
    "public_key": "-----BEGIN PUBLIC KEY-----..."
  },
  "hash": "SHA256_HASH",
  "signature": "DIGITAL_SIGNATURE",
  "ingest_timestamp": "ISO_TIMESTAMP",
  "source_ip": "127.0.0.1"
}
```

---

## Security Guarantees

| Property        | Mechanism             |
| --------------- | --------------------- |
| Integrity       | SHA-256 Hash          |
| Authenticity    | RSA Signature         |
| Non-repudiation | Private Key Signing   |
| Traceability    | Source ID + Timestamp |

---

## Project Structure

```text
S6_PROJECT_PHASE/
│
├── collector.py        # Log ingestion + security processing
├── consumer.py         # Kafka consumer
├── keygen.py           # RSA key generation
├── private.pem         # Private key (keep secure)
├── public.pem          # Public key (verification)
```

---

## Key Generation

Run once:

```bash
python keygen.py
```

---

## Kafka Setup

### Install Dependencies

```bash
sudo apt update
sudo apt install openjdk-17-jdk wget tar
```

---

### Download & Extract

```bash
wget https://archive.apache.org/dist/kafka/3.7.0/kafka_2.13-3.7.0.tgz
tar -xvf kafka_2.13-3.7.0.tgz
cd kafka_2.13-3.7.0
```

---

### Start Services

```bash
# Terminal 1
bin/zookeeper-server-start.sh config/zookeeper.properties

# Terminal 2
bin/kafka-server-start.sh config/server.properties
```

---

### Create Topic

```bash
bin/kafka-topics.sh --create \
--topic log_topic \
--bootstrap-server localhost:9092 \
--partitions 1 \
--replication-factor 1
```

---

## Running the Project

### 1. Start Collector

```bash
python collector.py
```

---

### 2. Generate Logs

```bash
logger "Test log message"
```

---

### 3. Run Consumer

```bash
python consumer.py
```

---

## Example Output

```text
[Collector] Evidence: {...}
[Consumer] Stored Log: {...}
```

---

## ⚠️ Important Notes

- Keep Kafka services running
- Do NOT expose `private.pem`
- UDP does not buffer logs → start collector first
- JSON is serialized with `sort_keys=True` for consistent hashing

---

## Future Work (Phase 3)

- Merkle Tree construction
- Blockchain anchoring
- Smart contract verification
- Distributed validation

---

## Reference

Project design follows the research architecture described in:

---

## Summary

This system transforms traditional logging into a:

> **secure, verifiable, and forensic-ready evidence pipeline**

by combining:

- real-time log ingestion
- cryptographic integrity
- digital signatures
- distributed storage

---
