import argparse

from security_harness.harness import run_harness


def main():
    parser = argparse.ArgumentParser(
        prog="security_harness",
        description="Security Harness",
    )

    parser.add_argument("src", type=str, help="Path of source to analyze")
    parser.add_argument("bugs", type=str, help="Path for bug reports")
    parser.add_argument("--dry_run", type=bool, help="Dry run flag")
    parser.add_argument("--config", type=str, default="~/.config/security_harness/config.toml", help="Path to config file")

    args = parser.parse_args()
    run_harness(args)



if __name__ == "__main__":
    main()