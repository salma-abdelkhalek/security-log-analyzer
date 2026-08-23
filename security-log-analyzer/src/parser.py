import re
import logging

logging.basicConfig(level=logging.WARNING)

pattern = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
    r"(?P<status>Accepted|Failed) password for "
    r"(?P<username>\w+) from "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+) "
    r"port \d+ ssh2"
)

def parse_logs():
    parsed_logs = []

    with open("sample_logs/auth.log", "r") as file:
        for line in file:
            line = line.strip()

            match = pattern.fullmatch(line)

            if not match:
                logging.warning(f"Skipping malformed line: {line}")
                continue

            log_data = match.groupdict()
            log_data["success"] = log_data["status"] == "Accepted"
            del log_data["status"]
            parsed_logs.append(log_data)

    return parsed_logs