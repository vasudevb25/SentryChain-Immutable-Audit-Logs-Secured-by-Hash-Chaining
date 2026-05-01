from kafka import KafkaConsumer
import json

consumer = KafkaConsumer(
    'log_topic',
    bootstrap_servers='localhost:9092',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

print("[Consumer] Listening...")

for message in consumer:
    print("[Stored Log]:", message.value)