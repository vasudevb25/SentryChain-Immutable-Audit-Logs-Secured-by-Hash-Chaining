# SentryChain: a Tamper-Evident Forensic Logging with Blockchain Integrity

A tamper-evident forensic logging system inspired by:

> **Putz et al. (2019)**
> _“A Secure and Auditable Logging Infrastructure Based on a Permissioned Blockchain”_
> Computers & Security Journal

This project implements a secure and auditable logging architecture that combines:

- real-time syslog collection,
- Apache Kafka streaming,
- SHA256 cryptographic hashing,
- RSA digital signatures,
- a permissioned blockchain auditing layer,
- Merkle tree verification,
- and forensic evidence validation.

The system is designed to preserve log integrity, detect tampering, and provide immutable forensic evidence for cybersecurity investigations.

## Overview

Traditional logging infrastructures are vulnerable to:

- log tampering,
- log deletion,
- centralized failure,
- and forensic manipulation.

Attackers who compromise a system often attempt to erase traces of malicious activity by modifying or deleting logs.

This project addresses these problems by combining:

- cryptographic hashing,
- digital signatures,
- immutable blockchain storage,
- and distributed auditability.

The implementation follows the architecture proposed in the research paper by Putz et al. and demonstrates a practical blockchain-backed forensic logging pipeline.

## Objectives

The primary objectives of this project are:

- Collect real-time Linux system logs
- Ensure integrity using SHA256 hashing
- Provide authenticity using RSA signatures
- Store logs using Apache Kafka
- Maintain immutable blockchain audit trails
- Detect tampering attempts
- Enable forensic verification of evidence
- Visualize blockchain transactions and blocks

## Features

### Secure Log Collection

- Real-time Linux syslog ingestion
- UDP syslog forwarding
- Structured JSON parsing
- Real-time evidence generation

### Cryptographic Security

- SHA256 hashing
- RSA digital signatures
- Tamper detection
- Non-repudiation

### Permissioned Blockchain

- Immutable audit trail
- Block-based transaction storage
- Merkle root generation
- Chain validation
- Duplicate transaction prevention

### Auditor Verification

- Hash recomputation
- RSA signature verification
- Blockchain proof validation
- Integrity confirmation

### Dashboard Visualization

- Blockchain explorer
- Live block monitoring
- Transaction visualization
- Verification interface

## Project Architecture

```text
                 ┌────────────────────┐
                 │   Linux Syslogs    │
                 │  (rsyslog/logger)  │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │    collector.py    │
                 │────────────────────│
                 │ Parse Syslogs      │
                 │ SHA256 Hashing     │
                 │ RSA Signatures     │
                 │ Create Evidence    │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │   Apache Kafka     │
                 │   Topic: log_topic │
                 └─────────┬──────────┘
                           │
                           ▼
                 ┌────────────────────┐
                 │   hashing_app.py   │
                 │────────────────────│
                 │ Consume Evidence   │
                 │ Submit to Chain    │
                 └─────────┬──────────┘
                           │
                           ▼
           ┌────────────────────────────────┐
           │      blockchain_node.py        │
           │────────────────────────────────│
           │ Verify Signatures              │
           │ Create Transactions            │
           │ Create Merkle Roots            │
           │ Commit Blocks                  │
           │ Maintain Blockchain            │
           └─────────┬──────────────────────┘
                     │
                     ▼
          ┌────────────────────────────┐
          │    blockchain_data.json    │
          │ Immutable Blockchain State │
          └────────────────────────────┘
                     │
         ┌───────────┴────────────┐
         ▼                        ▼
┌────────────────┐      ┌─────────────────┐
│   auditor.py   │      │ dashboard.html  │
│────────────────│      │─────────────────│
│ Verify Hashes  │      │ Block Explorer  │
│ Verify RSA     │      │ TX Monitoring   │
│ Verify Proof   │      │ Chain Statistics│
└────────────────┘      └─────────────────┘
```

## End-to-End Pipeline

```text
Linux System Logs
        ↓
rsyslog Forwarding
        ↓
UDP Transport (5514)
        ↓
collector.py
        ↓
Parse → Structure → Hash → Sign
        ↓
Kafka (log_topic)
        ↓
hashing_app.py
        ↓
Permissioned Blockchain
        ↓
Block Creation + Merkle Root
        ↓
Immutable Audit Trail
        ↓
Auditor Verification
        ↓
Dashboard Visualization
```

## Technologies Used

| Component            | Technology          |
| -------------------- | ------------------- |
| Programming Language | Python 3            |
| Streaming Platform   | Apache Kafka        |
| Log Collection       | rsyslog             |
| Cryptography         | SHA256 + RSA        |
| Blockchain API       | FastAPI             |
| Dashboard            | HTML/CSS/JavaScript |
| Data Storage         | JSON                |
| Networking           | UDP Syslog          |

## Folder Structure

```text
SecureLog/
│
├── collector.py
├── hashing_app.py
├── blockchain_node.py
├── auditor.py
├── dashboard.html
│
├── blockchain_data.json
├── sample_evidence.json
│
├── private.pem
├── public.pem
│
├── requirements.txt
└── README.md
```

## Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/SecureLog.git
cd SecureLog
```

### 2. Create Virtual Environment

```bash
python -m venv s6
source s6/bin/activate

Windows:
s6\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

## Apache Kafka Setup

### Install Dependencies

```bash
sudo apt update
sudo apt install openjdk-17-jdk wget tar
```

### Download & Extract Kafka

```bash
wget https://archive.apache.org/dist/kafka/3.7.0/kafka_2.13-3.7.0.tgz

tar -xvf kafka_2.13-3.7.0.tgz
cd kafka_2.13-3.7.0
```

### Create Kafka Topic

```bash
bin/kafka-topics.sh --create \
--topic log_topic \
--bootstrap-server localhost:9092 \
--partitions 1 \
--replication-factor 1
```

### Start ZooKeeper & Kafka Broker

```bash
Terminal 1
bin/zookeeper-server-start.sh config/zookeeper.properties

Terminal 2
bin/kafka-server-start.sh config/server.properties
```

## RSA Key Generation

Generate RSA public/private keypair:

```bash
python keygen.py
```

Generated files:

```text
private.pem
public.pem
```

## Linux Syslog Configuration

Edit rsyslog configuration:

```bash
sudo nano /etc/rsyslog.conf
```

Add:

```text
*.* @127.0.0.1:5514
```

Restart rsyslog:

```bash
sudo systemctl restart rsyslog
```

## Running the Project

### Terminal 1 — Blockchain Node

```bash
python blockchain_node.py
```

### Terminal 2 — Hashing Application

```bash
python hashing_app.py
```

### Terminal 3 — Collector

```bash
python collector.py
```

### Generate Test Logs

```bash
logger "secure logging test"
```

## Evidence Structure

Sample forensic evidence:

```json
{
  "payload": {
    "log": {
      "priority": 13,
      "timestamp": "2026-05-17T17:51:14",
      "host": "house-of-wits",
      "process": "profmoriarty",
      "message": "fresh verification test"
    },
    "source_id": "system_1",
    "public_key": "-----BEGIN PUBLIC KEY----- ..."
  },
  "hash": "3474f02b5e726f86...",
  "signature": "16a25d4f67cec18a...",
  "ingest_timestamp": "2026-05-17T12:21:14.494032",
  "source_ip": "127.0.0.1"
}
```

## Blockchain Structure

Each block contains:

- block hash
- previous block hash
- Merkle root
- timestamp
- committed transactions

Example:

```json
{
  "index": 1,
  "block_hash": "...",
  "prev_hash": "...",
  "merkle_root": "...",
  "transaction_count": 1,
  "transactions": [...]
}
```

## Auditor Verification

Run:

```bash
python auditor.py
```

Verification stages:

1. Recompute SHA256 hash
2. Verify RSA digital signature
3. Verify blockchain proof
4. Confirm immutable evidence

Expected output:

```text
[Auditor] Hash valid
[Auditor] Signature valid
[Auditor] Blockchain proof valid
```

## Dashboard

Open:

```text
dashboard.html
```

Features:

- Blockchain explorer
- Live block visualization
- Transaction monitoring
- Chain statistics
- Evidence verification

Data source:

```text
http://localhost:8000/chain
```

## Security Properties

| Property          | Implementation           |
| ----------------- | ------------------------ |
| Integrity         | SHA256 Hashing           |
| Authenticity      | RSA Signatures           |
| Non-Repudiation   | Private Key Signing      |
| Immutability      | Blockchain Storage       |
| Auditability      | Blockchain Verification  |
| Replay Protection | Duplicate Hash Rejection |

## Experimental Objectives

This implementation demonstrates:

- secure forensic logging,
- tamper-evident evidence generation,
- blockchain-backed integrity preservation,
- and cryptographic verification of system logs.

## Current Limitations

Current implementation includes:

- single-node permissioned blockchain,
- local Kafka deployment,
- simplified consensus mechanism.

Not yet implemented:

- PBFT consensus,
- multi-validator blockchain network,
- distributed replication,
- enterprise-scale deployment.

Distributed Byzantine consensus is where software projects evolve into psychological endurance events.

## Future Improvements

- Multi-node blockchain network
- PBFT consensus
- Hyperledger Fabric integration
- Windows Event Log support
- Docker deployment
- SIEM integration
- Advanced forensic analytics

## Research Reference

```text
Putz, Benedikt et al.
“A Secure and Auditable Logging Infrastructure
Based on a Permissioned Blockchain”
Computers & Security, 2019
```

## License

MIT License

## Author

Vasudev B  
Vighnesh B
