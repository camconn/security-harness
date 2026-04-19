import argparse

from security_harness.harness import run_harness


def main():
    parser = argparse.ArgumentParser(
        prog="security_harness",
        description="Security Harness",
    )

    parser.add_argument("src", type=str, help="Path of source to analyze")
    parser.add_argument("bugs", type=str, help="Path for bug reports")
    parser.add_argument("--dry_run", type=bool, default=False, help="Dry run flag")
    parser.add_argument("--config", type=str, default="~/.config/security_harness/config.toml", help="Path to config file")
    parser.add_argument("--excludes", type=str, action="append", default=[], metavar="DIR", help="Directory to exclude from ranking (relative to source root, repeatable)")
    parser.add_argument("--analysis_count", type=int, default=0, help="Number of analysis rounds to run after ranking (0 = skip)")
    parser.add_argument("--verify_count", type=int, default=0, help="Number of pending bug reports to verify after analysis (0 = skip)")
    parser.add_argument("--provider", type=str, default="openai", choices=["openai", "anthropic"], help="LLM provider")
    parser.add_argument("--model", type=str, default="gpt-5.4", help="Model name for the chosen provider")

    args = parser.parse_args()
    run_harness(args)



if __name__ == "__main__":
    main()