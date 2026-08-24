from datetime import datetime
from collections import deque


DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 60


def parse_time(ts):
    return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")


def group_failed_by_ip(logs):
    grouped = {}

    for entry in logs:
        if not entry["success"]:
            ip = entry["ip"]
            grouped.setdefault(ip, []).append(entry)

    return grouped


def detect_attacks(
    logs,
    threshold=DEFAULT_THRESHOLD,
    window_seconds=DEFAULT_WINDOW_SECONDS
):
    grouped = group_failed_by_ip(logs)
    flagged = {}

    for ip, attempts in grouped.items():

        attempts.sort(key=lambda e: parse_time(e["timestamp"]))

        window = deque()
        attack_attempts = []
        attack_detected = False

        for entry in attempts:
            current_time = parse_time(entry["timestamp"])

            window.append(entry)

            while (
                current_time - parse_time(window[0]["timestamp"])
            ).total_seconds() > window_seconds:
                window.popleft()

            if len(window) >= threshold:
                attack_detected = True

                attack_attempts = list(window)

        if attack_detected:

            flagged[ip] = {
                "attempt_count": len(attack_attempts),
                "first_attempt": attack_attempts[0]["timestamp"],
                "last_attempt": attack_attempts[-1]["timestamp"],
                "usernames": list(
                    {entry["username"] for entry in attack_attempts}
                ),
            }

    return flagged
