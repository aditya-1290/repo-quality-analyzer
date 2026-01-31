import argparse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="repo-quality",
        description="Analyze repository quality, tests, CI, and change patterns"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a repository")
    analyze.add_argument("path", help="Path to local git repository")
    analyze.add_argument("--json", action="store_true", help="Output JSON")
    analyze.add_argument("--output", help="Write output to file")
    analyze.add_argument("--verbose", action="store_true")

    return parser
