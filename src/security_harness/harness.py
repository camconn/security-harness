from argparse import Namespace
from collections.abc import Generator
from pathlib import Path
import re
import subprocess

from langchain_core.messages import HumanMessage, SystemMessage

from security_harness.agent import make_llm, make_analysis_agent
from security_harness.state import State
from security_harness.tools.files import make_file_tools


PROMPT_BASE = """
You are working on the security research team. Your task is to find potential security
issues and vulnerabilities in a legacy codebase. You want to find issues before they
are found and reported or exploited in the wild.
"""

FILE_RANK_PROMPT = PROMPT_BASE + '\n' + """
Your current task is to rank the likelihood certain files have security related
code on a scale from 0 (not likely) to 10 (extremely likely). Look at the file
and examine it for its security properties.

For example:

File: src/main/kotlin/com/example/controller/AuthenticationController.kt
Score: 10.0
File: src/main/kotlin/com/example/service/AuthenticationService.kt
Score: 10.0
File: src/main/kotlin/com/example/repository/UserRepository.kt
Score: 8.0
File: src/main/kotlin/com/example/controller/MostMovedStocks.kt
Score: 1.0
File: src/main/kotlin/com/example/controller/ChatController.kt
Score: 6.0
File: src/main/resources/application.properties
Score: 6.0
File: infra/pulumi/__main__.py
Score: 6.0
File: README.md
Score: 0.0

Use the read_file tool to read the file's contents before scoring it.

Rank the following file:"""


def run_harness(args: Namespace) -> None:
    is_dry_run = args.dry_run
    print(f"Is dry run: {is_dry_run}")

    src_path = Path(args.src).expanduser()
    print(f"Source to examine: {src_path}")

    bugs = Path(args.bugs).expanduser()
    bugs.mkdir(parents=True, exist_ok=True)
    print(f"Analysis storage: {bugs}")

    state = State(
        src_path = str(src_path),
        bugs_path = str(bugs),
    )

    src_files = set(list_tracked_files(src_path))
    db_files = {f.path: f for f in state.get_file_rankings()}
    db_paths = set(db_files.keys())

    already_ranked = [db_files[p] for p in src_files & db_paths]
    to_analyze = sorted(src_files - db_paths)
    to_delete = sorted(db_paths - src_files)

    if to_delete:
        print(f"Deleting {len(to_delete)} file(s) from database...")
        state.delete_file_ranking(to_delete)

    if not to_analyze or is_dry_run:
        return

    llm = make_llm(args.provider, args.model)
    file_tools = make_file_tools(src_path)
    agent = make_analysis_agent(llm, file_tools)

    print(f"Ranking {len(to_analyze)} new file(s)...")
    rankings = rank_files(agent, to_analyze)
    for path, score in rankings:
        state.insert_file_ranking(path, score)
        print(f"  {score:.1f}  {path}")


def rank_files(agent, files: list[str]) -> Generator[tuple[str, float], None, None]:
    system_message = SystemMessage(content=FILE_RANK_PROMPT)
    for path in files:
        print(f"Ranking {path}")
        response = agent.invoke({"messages": [
            system_message,
            HumanMessage(content=f"File: {path}\nScore:"),
        ]})
        last_message = response["messages"][-1]
        content = last_message.content
        if isinstance(content, list):
            content = " ".join(p["text"] for p in content if p.get("type") == "text")
        match = re.search(r"Score:\s*(\d+(?:\.\d+)?)", content)
        if match:
            score = float(match.group(1))
        else:
            print(f"Invalid score for {path}: <<{content}>>")
            score = 0.0
        yield path, score

def list_tracked_files(repo_path: str | Path) -> list[str]:
    repo_path = Path(repo_path)

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
        shell=False,
    )

    return result.stdout.splitlines()
