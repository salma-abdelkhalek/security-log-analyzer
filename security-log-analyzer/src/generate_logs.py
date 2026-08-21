import random
from datetime import datetime, timedelta
import os

IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "10.0.0.5",
    "172.16.0.8",
    "10.0.0.10",
    "10.0.0.20",
    "172.16.1.5",
    "192.168.2.10"
]

USERNAMES = [
    "admin",
    "root",
    "ahmed",
    "sara",
    "mohamed",
    "test"
]

def generate_normal_log(timestamp):
    ip = random.choice(IPS)
    username = random.choice(USERNAMES)
    success = random.choice([True, True, True, True, False])

    if success:
        status = "Accepted password"
    else:
        status = "Failed password"

    port = random.randint(30000, 60000)

    return (
        f"{timestamp} {status} for {username} "
        f"from {ip} port {port} ssh2"
    )

def generate_attack_burst(start_time, attack_ip, attempts=8):
    logs = []

    for i in range(attempts):
        timestamp = start_time + timedelta(seconds=i * 3)
        username = random.choice(USERNAMES)
        port = random.randint(30000, 60000)

        log = (
            f"{timestamp} Failed password for {username} "
            f"from {attack_ip} port {port} ssh2"
        )

        logs.append(log)

    return logs

start_time = datetime(2026, 8, 20, 19, 0, 0)
logs = []

current_time = start_time
for _ in range(20):
    log = generate_normal_log(current_time)
    logs.append(log)

    current_time += timedelta(seconds=random.randint(5, 20))

attack_logs = generate_attack_burst(
    current_time,
    "192.168.1.50",
    attempts=7
)
logs.extend(attack_logs)

current_time += timedelta(seconds=30)

for _ in range(10):
    log = generate_normal_log(current_time)
    logs.append(log)

    current_time += timedelta(seconds=random.randint(5, 20))


current_time += timedelta(seconds=120)

attack_logs = generate_attack_burst(
    current_time,
    "10.0.0.99",
    attempts=8
)
logs.extend(attack_logs)

logs.sort()

os.makedirs("sample_logs", exist_ok=True)

with open("sample_logs/auth.log", "w") as file:
    for log in logs:
        file.write(log + "\n")