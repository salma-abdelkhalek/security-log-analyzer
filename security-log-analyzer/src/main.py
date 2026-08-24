import argparse
from detector import detect_attacks
from report import print_report, export_json, export_csv

def main():
    parser = argparse.ArgumentParser(description="SSH Brute-Force Log Analyzer")
    parser.add_argument("--file", default="sample_logs/auth.log", help="Path to log file")
    parser.add_argument("--threshold", type=int, default=5, help="Failed attempts to trigger a flag")
    parser.add_argument("--window", type=int, default=60, help="Time window in seconds")
    parser.add_argument("--export", choices=["csv", "json"], help="Export format")
    args = parser.parse_args()

   
    from parser import parse_logs
    logs = parse_logs(args.file)

    results = detect_attacks(logs, threshold=args.threshold, window_seconds=args.window)
    print_report(results)

    if args.export == "json":
        export_json(results)
    elif args.export == "csv":
        export_csv(results)

if __name__ == "__main__":
    main()