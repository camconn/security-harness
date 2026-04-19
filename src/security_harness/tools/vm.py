import subprocess

from langchain_core.tools import tool


def make_vm_tools(host: str, ssh_key_path: str | None = None, timeout: int = 30) -> list:
    ssh_base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no"]
    if ssh_key_path:
        ssh_base += ["-i", ssh_key_path]

    @tool
    def run_command(command: str) -> str:
        """Execute a shell command on the target VM and return its output."""
        result = subprocess.run(
            [*ssh_base, host, command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"
        return output

    @tool
    def read_remote_file(path: str) -> str:
        """Read the contents of a file on the target VM."""
        result = subprocess.run(
            [*ssh_base, host, f"cat -- {path}"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Could not read {path!r}: {result.stderr.strip()}")
        return result.stdout

    return [run_command, read_remote_file]
