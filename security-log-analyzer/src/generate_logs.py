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
    "192.168.2.10",
    "192.168.1.50",
    "10.0.0.99",
    "172.16.5.20",
    "192.168.10.15"
]


USERNAMES = [
    "admin",
    "root",
    "ahmed",
    "sara",
    "mohamed",
    "test",
    "user",
    "guest"
]


def generate_normal_log(timestamp):
    ip = random.choice(IPS)
    username = random.choice(USERNAMES)

    success = random.choice([
        True,
        True,
        True,
        True,
        False
    ])

    if success:
        status = "Accepted password"
    else:
        status = "Failed password"

    port = random.randint(30000, 60000)

    return (
        f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} "
        f"{status} for {username} "
        f"from {ip} port {port} ssh2"
    )


def generate_attack_burst(start_time, attack_ip, attempts):
    logs = []
    current_time = start_time

    for _ in range(attempts):

        username = random.choice(USERNAMES)
        port = random.randint(30000, 60000)

        log = (
            f"{current_time.strftime('%Y-%m-%d %H:%M:%S')} "
            f"Failed password for {username} "
            f"from {attack_ip} port {port} ssh2"
        )

        logs.append(log)

        current_time += timedelta(
            seconds=random.randint(1, 3)
        )

    return logs


def generate_logs():

    logs = []

    start_time = datetime(
        2026,
        8,
        20,
        random.randint(8, 20),
        random.randint(0, 59),
        random.randint(0, 59)
    )

    current_time = start_time

    normal_before = random.randint(15, 30)

    for _ in range(normal_before):

        logs.append(
            generate_normal_log(current_time)
        )

        current_time += timedelta(
            seconds=random.randint(5, 25)
        )

    number_of_attacks = random.randint(2, 4)

    attack_ips = random.sample(
        IPS,
        number_of_attacks
    )

    for attack_ip in attack_ips:

        attempts = random.randint(5, 18)

        attack_logs = generate_attack_burst(
            current_time,
            attack_ip,
            attempts
        )

        logs.extend(attack_logs)

        current_time += timedelta(
            seconds=random.randint(90, 180)
        )

        normal_between = random.randint(5, 15)

        for _ in range(normal_between):

            logs.append(
                generate_normal_log(current_time)
            )

            current_time += timedelta(
                seconds=random.randint(5, 25)
            )

    normal_after = random.randint(10, 25)

    for _ in range(normal_after):

        logs.append(
            generate_normal_log(current_time)
        )

        current_time += timedelta(
            seconds=random.randint(5, 25)
        )

    logs.sort()

    BASE_DIR = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )

    log_dir = os.path.join(
        BASE_DIR,
        "sample_logs"
    )

    os.makedirs(
        log_dir,
        exist_ok=True
    )

    output_path = os.path.join(
        log_dir,
        "auth.log"
    )

    with open(output_path, "w") as file:
        for log in logs:
            file.write(log + "\n")

    print("New random logs generated successfully!")
    print(f"Total log entries: {len(logs)}")
    print(f"Attacks injected: {number_of_attacks}")
    print(f"Saved to: {output_path}")


if __name__ == "__main__":
    generate_logs()