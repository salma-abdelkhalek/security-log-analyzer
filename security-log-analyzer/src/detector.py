
from datetime import datetime
from collections import deque

def parse_time(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")

fake_logs = [
    {"timestamp": "2026-08-20 14:32:01", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:05", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:10", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:15", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:20", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:35:00", "ip": "192.168.1.10", "username": "bob", "success": True},
]

fake_logs = [
    {"timestamp": "2026-08-20 14:32:01", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:05", "ip": "10.0.0.5", "username": "root", "success": False},
    {"timestamp": "2026-08-20 14:32:10", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:15", "ip": "10.0.0.5", "username": "admin", "success": False},
    {"timestamp": "2026-08-20 14:32:20", "ip": "10.0.0.5", "username": "admin", "success": False},
    # Normal: fails spread far apart, should NOT be flagged
    {"timestamp": "2026-08-20 10:00:00", "ip": "192.168.1.20", "username": "bob", "success": False},
    {"timestamp": "2026-08-20 10:15:00", "ip": "192.168.1.20", "username": "bob", "success": False},
    {"timestamp": "2026-08-20 14:35:00", "ip": "192.168.1.10", "username": "carol", "success": True},
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


THRESHOLD = 5
WINDOW_SECONDS = 60

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 60

def detect_attacks(logs, threshold=DEFAULT_THRESHOLD, window_seconds=DEFAULT_WINDOW_SECONDS):
    grouped = group_failed_by_ip(logs)
    flagged = {}

    for ip, attempts in grouped.items():
        attempts.sort(key=lambda e: parse_time(e["timestamp"]))
        window = deque()

        for entry in attempts:
            t = parse_time(entry["timestamp"])
            window.append(entry)

            while (t - parse_time(window[0]["timestamp"])).total_seconds() > window_seconds:
                window.popleft()

            if len(window) >= threshold:
                flagged[ip] = {
                    "attempt_count": len(window),
                    "first_attempt": window[0]["timestamp"],
                    "last_attempt": window[-1]["timestamp"],
                    "usernames": list({e["username"] for e in window}),
                }
                break

    return flagged

if __name__ == "__main__":
    results = detect_attacks(fake_logs)
    for ip, info in results.items():
        print(f"ATTACK from {ip}: {info}")

