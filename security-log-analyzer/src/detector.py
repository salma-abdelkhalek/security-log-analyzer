
from datetime import datetime

# Fake data matching the shared format — some normal, some an "attack"
fake_logs = [
    {"timestamp": "2026-08-20 14:32:01", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:05", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:10", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:15", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:20", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:35:00", "ip": "192.168.1.10", "username": "bob", "success": True},
]
def group_failed_by_ip(logs):
    grouped = {}
    for entry in logs:
        if not entry["success"]:
            ip = entry["ip"]
            grouped.setdefault(ip, []).append(entry)
    return grouped

if __name__ == "__main__":
    grouped = group_failed_by_ip(fake_logs)
    for ip, attempts in grouped.items():
        print(f"{ip}: {len(attempts)} failed attempts")

