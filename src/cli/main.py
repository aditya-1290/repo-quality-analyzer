import sys
from .arguments import build_parser
from .runner import run_analysis, render

def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "analyze":
        result = run_analysis(args.path)
        output = render(result, args.json)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        else:
            print(output)

if __name__ == "__main__":
    main(sys.argv[1:])
