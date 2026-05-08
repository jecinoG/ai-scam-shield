"""
evaluate.py — Batch evaluation script for AI Scam Shield

Runs the detection pipeline against the sample dataset and prints
a summary of results per category. Also supports running a single
message from the command line.

Usage:
    python evaluate.py                     # run against datasets/scam_samples.csv
    python evaluate.py --message "..."     # analyze a single message
    python evaluate.py --verbose           # show signal breakdown per message

This isn't a proper ML eval (no precision/recall — we don't have ground
truth labels in the formal sense yet). It's more of a sanity-check /
smoke-test tool to catch regressions when rules are changed.

TODO: Add label column to dataset and compute proper metrics.
"""

import csv
import argparse
import sys
import os
from collections import defaultdict
from typing import List, Dict

# Adjust path so this can be run from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from risk_classifier import assess_message


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

LEVEL_COLORS = {
    "low": "\033[32m",      # green
    "medium": "\033[33m",   # yellow
    "high": "\033[31m",     # red
}
RESET = "\033[0m"


def colored(text: str, level: str) -> str:
    color = LEVEL_COLORS.get(level, "")
    return f"{color}{text}{RESET}"


def print_separator(char="-", width=70):
    print(char * width)


# ---------------------------------------------------------------------------
# Core eval logic
# ---------------------------------------------------------------------------

def evaluate_dataset(csv_path: str, verbose: bool = False) -> List[Dict]:
    """
    Read CSV and run each message through the detector.
    CSV expected columns: id, category, message
    (category is the expected/labelled scam type — used for display only)
    """
    if not os.path.exists(csv_path):
        print(f"ERROR: Dataset file not found at {csv_path}")
        sys.exit(1)

    results = []

    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"\nAI Scam Shield — Evaluation Run")
    print(f"Dataset: {csv_path} ({len(rows)} messages)")
    print_separator("=")

    for row in rows:
        msg_id = row.get("id", "?")
        expected_cat = row.get("category", "unknown")
        message = row.get("message", "").strip()

        if not message:
            continue

        result = assess_message(message)

        record = {
            "id": msg_id,
            "expected_category": expected_cat,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "detected_categories": result.detected_categories,
            "explanation": result.explanation,
            "num_signals": len(result.signal_breakdown),
        }
        results.append(record)

        level_str = colored(f"{result.risk_level.upper():8}", result.risk_level)
        score_str = colored(f"[{result.risk_score:3d}]", result.risk_level)
        cats = ", ".join(result.detected_categories[:3]) or "none"
        truncated_msg = message[:60].replace("\n", " ") + ("..." if len(message) > 60 else "")

        print(f"#{msg_id:>3} {score_str} {level_str} | expected: {expected_cat:<30} | {truncated_msg}")

        if verbose and result.signal_breakdown:
            for sig in result.signal_breakdown:
                print(f"       ↳ [{sig['category']}] w={sig['weight']:.1f} — {sig['reason']}")

    return results


def print_summary(results: List[Dict]):
    """Print aggregate stats over all evaluated messages."""
    if not results:
        print("No results to summarize.")
        return

    print_separator("=")
    print("SUMMARY")
    print_separator()

    total = len(results)
    level_counts = defaultdict(int)
    category_counts = defaultdict(int)
    score_total = 0

    for r in results:
        level_counts[r["risk_level"]] += 1
        score_total += r["risk_score"]
        for cat in r["detected_categories"]:
            category_counts[cat] += 1

    avg_score = score_total / total if total > 0 else 0

    print(f"Total messages analyzed : {total}")
    print(f"Average risk score      : {avg_score:.1f}")
    print()
    print("Risk level distribution:")
    for level in ["high", "medium", "low"]:
        count = level_counts[level]
        pct = (count / total * 100) if total > 0 else 0
        bar = "█" * int(pct / 3)
        print(f"  {level.upper():8} {count:4d} ({pct:5.1f}%) {colored(bar, level)}")

    print()
    print("Most frequently triggered categories:")
    sorted_cats = sorted(category_counts.items(), key=lambda x: x[1], reverse=True)
    for cat, count in sorted_cats[:10]:
        print(f"  {cat:<35} {count:3d} messages")

    print_separator()


def evaluate_single(message: str, verbose: bool = False):
    """Analyze and print a single message."""
    result = assess_message(message)

    print("\nAI Scam Shield — Single Message Analysis")
    print_separator("=")
    print(f"Message     : {message[:100]}{'...' if len(message) > 100 else ''}")
    print_separator()
    score_display = colored(str(result.risk_score), result.risk_level)
    level_display = colored(result.risk_level.upper(), result.risk_level)
    print(f"Risk Score  : {score_display}/100")
    print(f"Risk Level  : {level_display}")
    print(f"Categories  : {', '.join(result.detected_categories) or 'none'}")
    print(f"Explanation : {result.explanation}")

    if verbose and result.signal_breakdown:
        print()
        print("Signal breakdown:")
        for sig in result.signal_breakdown:
            print(f"  [{sig['category']}] weight={sig['weight']:.1f}")
            print(f"    matched : {sig['matched']}")
            print(f"    reason  : {sig['reason']}")

    print_separator("=")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AI Scam Shield — Evaluation Tool"
    )
    parser.add_argument(
        "--message", "-m",
        type=str,
        help="Analyze a single message string.",
    )
    parser.add_argument(
        "--dataset", "-d",
        type=str,
        default="datasets/scam_samples.csv",
        help="Path to CSV dataset (default: datasets/scam_samples.csv)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed signal breakdown per message.",
    )

    args = parser.parse_args()

    if args.message:
        evaluate_single(args.message, verbose=args.verbose)
    else:
        results = evaluate_dataset(args.dataset, verbose=args.verbose)
        print_summary(results)


if __name__ == "__main__":
    main()
