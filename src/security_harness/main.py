import argparse
import threading
from pathlib import Path

import uvicorn

from security_harness.harness import run_harness
from security_harness.live_state import LiveState
from security_harness.state import State
from security_harness.web import create_app


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
    parser.add_argument("--analysis_count", type=int, default=-1, help="Number of analysis rounds to run after ranking (0 = skip, negative = run indefinitely)")
    parser.add_argument("--verify_count", type=int, default=0, help="Number of pending bug reports to verify after analysis (0 = skip)")
    parser.add_argument("--provider", type=str, default="openai", choices=["openai", "anthropic"], help="LLM provider")
    parser.add_argument("--model", type=str, default="gpt-5.4", help="Model name for the chosen provider")
    parser.add_argument("--dedup", action="store_true", default=False, help="Enable LLM-based duplicate detection when storing new bug reports")
    parser.add_argument("--dedup_batch_size", type=int, default=10, metavar="N", help="Number of existing bug reports compared per LLM call during dedup (default: 10)")
    parser.add_argument("--web_port", type=int, default=9999, metavar="PORT", help="Port for the web dashboard (0 = disabled, default: 9999)")

    args = parser.parse_args()

    bugs = Path(args.bugs).expanduser()
    bugs.mkdir(parents=True, exist_ok=True)

    live = LiveState()
    state = State(src_path=str(Path(args.src).expanduser()), bugs_path=str(bugs))
    state.setup_database()

    server = None
    if args.web_port:
        app = create_app(state, live)
        config = uvicorn.Config(app, host="0.0.0.0", port=args.web_port, log_level="warning")
        server = uvicorn.Server(config)
        server.install_signal_handlers = False
        web_thread = threading.Thread(target=server.run, daemon=True)
        web_thread.start()
        print(f"Web dashboard: http://localhost:{args.web_port}")

    try:
        run_harness(args, live=live)
        if server is not None:
            print("No work to do. Dashboard running — press Ctrl+C to exit.")
            while True:
                web_thread.join(timeout=1)
    except KeyboardInterrupt:
        pass
    finally:
        if server is not None:
            server.should_exit = True


if __name__ == "__main__":
    main()
