import csv
import json

def print_report(flagged):
    if not flagged:
        print("No brute-force attacks detected.")
        return

    print(f"{'IP Address':<20}{'Attempts':<10}{'First Seen':<22}{'Last Seen':<22}{'Usernames'}")
    print("-" * 100)
    for ip, info in flagged.items():
        usernames = ", ".join(info["usernames"])
        print(f"{ip:<20}{info['attempt_count']:<10}{info['first_attempt']:<22}{info['last_attempt']:<22}{usernames}")

def export_json(flagged, filepath="report.json"):
    with open(filepath, "w") as f:
        json.dump(flagged, f, indent=2)
    print(f"Report saved to {filepath}")

def export_csv(flagged, filepath="report.csv"):
    with open(filepath, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Attempt Count", "First Attempt", "Last Attempt", "Usernames"])
        for ip, info in flagged.items():
            writer.writerow([ip, info["attempt_count"], info["first_attempt"], info["last_attempt"], ", ".join(info["usernames"])])
    print(f"Report saved to {filepath}")