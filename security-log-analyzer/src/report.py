import csv
import json


def print_report(flagged):

    if not flagged:
        print("No brute-force attacks detected.")
        return

    print(
        f"{'IP Address':<20}"
        f"{'Attempts':<10}"
        f"{'First Seen':<22}"
        f"{'Last Seen':<22}"
        f"{'Usernames'}"
    )

    print("-" * 100)

    for ip, info in flagged.items():

        usernames = ", ".join(
            info["usernames"]
        )

        print(
            f"{ip:<20}"
            f"{info['attempt_count']:<10}"
            f"{info['first_attempt']:<22}"
            f"{info['last_attempt']:<22}"
            f"{usernames}"
        )


def export_json(flagged, filepath="report.json"):

    with open(filepath, "w") as file:

        json.dump(
            flagged,
            file,
            indent=2
        )

    print(f"Report saved to {filepath}")


def export_csv(flagged, filepath="report.csv"):

    with open(
        filepath,
        "w",
        newline=""
    ) as file:

        writer = csv.writer(file)

        writer.writerow([
            "IP",
            "Attempt Count",
            "First Attempt",
            "Last Attempt",
            "Usernames"
        ])

        for ip, info in flagged.items():

            writer.writerow([
                ip,
                info["attempt_count"],
                info["first_attempt"],
                info["last_attempt"],
                ", ".join(info["usernames"])
            ])

    print(f"Report saved to {filepath}")