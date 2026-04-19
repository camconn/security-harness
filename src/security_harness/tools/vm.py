import subprocess

from langchain_core.tools import tool


def make_vm_tools(host: str, ssh_key_path: str | None = None, timeout: int = 30) -> list:
    ssh_base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"]
    if ssh_key_path:
        ssh_base += ["-i", ssh_key_path]

    @tool
    def run_command(command: str) -> str:
        """Execute a shell command on the target VM and return its output."""
        try:
            result = subprocess.run(
                [*ssh_base, host, command],
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

    @tool
    def read_remote_file(path: str) -> str:
        """Read the contents of a file on the target VM."""
        try:
            result = subprocess.run(
                [*ssh_base, host, f"cat -- {path}"],
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
        if result.returncode != 0:
            return f"Error reading {path!r}: {result.stderr.strip()}"
        return result.stdout

    return [run_command, read_remote_file]
