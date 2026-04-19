import shlex
import subprocess
from pathlib import Path

from langchain_core.tools import tool


COMMAND_WHITELIST = {
    "curl", "wget",
    "python", "python3",
    "gcc", "clang", "cc", "c++", "clang++", "g++",
    "go", "rustc", "cargo", "java", "javac",
    "echo", "printf",
    "telnet", "nc", "ncat",
    "cat", "ls",
    "jq",
    "head", "tail", "less",
}


def make_sandbox_tools(sandbox_dir: str | Path, timeout: int = 30) -> list:
    sandbox = Path(sandbox_dir).resolve()

    @tool
    def write_file(path: str, content: str) -> str:
        """Write content to a file in the sandbox working directory."""
        target = (sandbox / path).resolve()
        if not target.is_relative_to(sandbox):
            return f"Error: {path!r} is outside the sandbox"
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content)
        except Exception as e:
            return f"Error writing {path!r}: {e}"
        return f"Written {len(content)} bytes to {path}"

    @tool
    def run_command(command: str) -> str:
        """Execute a whitelisted shell command in the sandbox working directory."""
        try:
            tokens = shlex.split(command)
        except ValueError as e:
            return f"Error: could not parse command: {e}"
        if not tokens:
            return "Error: empty command"
        executable = Path(tokens[0]).name
        if executable not in COMMAND_WHITELIST:
            allowed = ", ".join(sorted(COMMAND_WHITELIST))
            return f"Error: {executable!r} is not allowed. Allowed commands: {allowed}"
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=sandbox,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            output = f"Error: command timed out after {timeout}s"
            if e.stdout:
                output += f"\n{e.stdout if isinstance(e.stdout, str) else e.stdout.decode(errors='replace')}"
            if e.stderr:
                output += f"\n[stderr]\n{e.stderr if isinstance(e.stderr, str) else e.stderr.decode(errors='replace')}"
            return output
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"
        return output

    return [write_file, run_command]
