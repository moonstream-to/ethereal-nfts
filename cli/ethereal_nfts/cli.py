import argparse

from .version import VERSION

def generate_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ethereal-nfts: Command line interface to interact with Ethereal NFTs"
    )
    parser.add_argument("-v", "--version", action="version", version=VERSION)
    parser.set_defaults(func=lambda _: parser.print_help())

    subparsers = parser.add_subparsers()

    return parser


def main() -> None:
    parser = generate_cli()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
