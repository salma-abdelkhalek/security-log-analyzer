import argparse
import os

from detector import detect_attacks
from parser import parse_logs
from report import print_report, export_json, export_csv


BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DEFAULT_LOG_PATH = os.path.join(
    BASE_DIR,
    "sample_logs",
    "auth.log"
)


def main():

    parser = argparse.ArgumentParser(
        description="SSH Brute-Force Log Analyzer"
    )

    parser.add_argument(
        "--file",
        default=DEFAULT_LOG_PATH,
        help="Path to log file"
    )

    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts to trigger a flag"
    )

    parser.add_argument(
        "--window",
        type=int,
        default=60,
        help="Time window in seconds"
    )

    parser.add_argument(
        "--export",
        choices=["csv", "json"],
        help="Export format"
    )

    args = parser.parse_args()

    # Parse log file
    logs = parse_logs(args.file)

    # Detect brute-force attacks
    results = detect_attacks(
        logs,
        threshold=args.threshold,
        window_seconds=args.window
    )

    # Print results
    print_report(results)

    # Export results if requested
    if args.export == "json":
        export_json(results)

    elif args.export == "csv":
        export_csv(results)


if __name__ == "__main__":
    main()