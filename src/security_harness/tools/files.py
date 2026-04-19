from pathlib import Path

from langchain_core.tools import tool


def make_file_tools(sandbox_dir: str | Path) -> list:
    sandbox = Path(sandbox_dir).resolve()

    @tool
    def read_file(path: str) -> str:
        """Read a file's contents. Path must be relative to the sandboxed source directory."""
        target = (sandbox / path).resolve()
        if not target.is_relative_to(sandbox):
            raise PermissionError(f"Access denied: {path!r} is outside the sandbox")
        if not target.is_file():
            raise FileNotFoundError(f"Not a file: {path!r}")
        return target.read_text()

    @tool
    def list_directory(path: str = ".") -> str:
        """List entries in a directory. Path must be relative to the sandboxed source directory."""
        target = (sandbox / path).resolve()
        if not target.is_relative_to(sandbox):
            raise PermissionError(f"Access denied: {path!r} is outside the sandbox")
        if not target.is_dir():
            raise NotADirectoryError(f"Not a directory: {path!r}")
        entries = sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name))
        return "\n".join(str(e.relative_to(sandbox)) for e in entries)

    return [read_file, list_directory]
