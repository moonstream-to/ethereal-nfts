import argparse

from .BasicEthereal import generate_cli as basic_generate_cli
from .version import VERSION


def generate_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ethereal-nfts: Command line interface to interact with Ethereal NFTs"
    )
    parser.add_argument("-v", "--version", action="version", version=VERSION)
    parser.set_defaults(func=lambda _: parser.print_help())

    subparsers = parser.add_subparsers()

    basic_usage = "Work with a basic Ethereal NFT, which gives signing authority to the account which owns the Ethereal contract"
    basic_parser = basic_generate_cli()
    subparsers.add_parser(
        "basic",
        description=basic_usage,
        help=basic_usage,
        parents=[basic_parser],
        add_help=False,
    )

    return parser


def main() -> None:
    parser = generate_cli()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
