import win32evtlog
import json
from kafka import KafkaProducer
from datetime import datetime

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

server = 'localhost'
log_type = 'Security'

hand = win32evtlog.OpenEventLog(server, log_type)

flags = win32evtlog.EVENTLOG_BACKWARDS_READ | \
        win32evtlog.EVENTLOG_SEQUENTIAL_READ

print("[Windows Collector] Listening for logs...")

while True:
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    if events:
        for event in events:

            log = {
                "source": "windows",
                "event_id": event.EventID,
                "event_type": event.EventType,
                "timestamp": event.TimeGenerated.Format(),
                "computer": event.ComputerName,
                "category": event.EventCategory
            }

            print(log)

            producer.send("log_topic", log)
            producer.flush()