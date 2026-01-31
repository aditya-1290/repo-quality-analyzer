from src.cli.arguments import build_parser

def test_analyze_command_parses_path():
    parser = build_parser()
    args = parser.parse_args(["analyze", "/tmp/repo"])
    assert args.command == "analyze"
    assert args.path == "/tmp/repo"
