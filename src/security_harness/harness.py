from argparse import Namespace
from collections.abc import Generator
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from pathlib import Path
import re
import subprocess
import tempfile

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
import uuid

from security_harness.agent import make_llm, make_analysis_agent
from security_harness.state import BugReport, FileRanking, ReproAttempt, State
from security_harness.tools.files import make_file_tools, BLOCKED_NAMES, BLOCKED_DIRS
from security_harness.tools.local import make_sandbox_tools


def _load_project_notes(bugs_path: Path) -> str | None:
    notes_file = bugs_path / "NOTES.md"
    if notes_file.exists():
        content = notes_file.read_text().strip()
        return content if content else None
    return None


def _load_verify_instructions(bugs_path: Path) -> str | None:
    verify_file = bugs_path / "VERIFY.md"
    if verify_file.exists():
        content = verify_file.read_text().strip()
        return content if content else None
    return None


def _with_notes(base_prompt: str, notes: str | None) -> str:
    if not notes:
        return base_prompt
    return base_prompt + f"\n\n## Project Context\n\nThe following notes describe how this project is deployed, its threat model, and other relevant context. Use this when making your assessments:\n\n{notes}\n"


def _with_verify_instructions(base_prompt: str, instructions: str | None) -> str:
    if not instructions:
        return base_prompt
    return base_prompt + f"\n\n## Verification Environment\n\nThe following instructions describe the staging environment to use when running proof-of-concept commands. Follow them exactly when crafting requests:\n\n{instructions}\n"


SKIP_EXTENSIONS = {
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp", ".tiff", ".tif", ".heif",
    # Video
    ".mp4", ".mov", ".avi", ".mkv", ".webm",
    # Audio
    ".mp3", ".wav", ".ogg", ".flac", ".aac",
    # Documents
    ".pdf", ".docx", ".doc"
    # Other
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".zip", ".tar", ".jar", ".exe", ".gz", ".bz2", ".7z",
}

PROMPT_BASE = """
You are working on the security research team. Your task is to find potential security
issues and vulnerabilities in a legacy codebase. You want to find issues before they
are found and reported or exploited in the wild.
"""

FILE_RANK_TASK = PROMPT_BASE + '\n' + """
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

FILE_ANALYSIS_TASK = PROMPT_BASE + '\n' + """
You have been assigned a file to analyze. Your task is to deep-analyze the file
and identify any security vulnerabilities or issues.

If there are any issues found, provide a bug report with a title, explanation,
description, and proof of concept for the code. If you fail to find an issue, simply
fill out the same format response with the "failed" status. You may fill out multiple
issues by placing the text `<next>` in your response.

Sample format response format:

Analysis File: <filename>

File: <filename>
Status: "Complete" | "Failed"
Severity: "Low" | "Medium" | "High" | "Critical" (<CVE-Score>)
Title: <title>
Description:
<description>
Proof of Concept:
<proof_of_concept>

Examples:

---

Analysis File: src/kotlin/main/com/example/service/AuthenticationService.kt

File: src/kotlin/main/com/example/service/AuthenticationService.kt
Status: Complete
Severity: High (9.0)
Title: Authentication Service XSS
Description:
The authentication service is vulnerable to XSS attacks.
Proof of Concept:
The service is vulnerable to XSS attacks and does not checks for hostnames and performs sensitive operations
with GET requests parameters.
curl 'http://localhost:8080/api/v1/users/me/reset?updatePasswordTo=hunter2' -H 'Host: malicious.website'

---

Analysis File: src/kotlin/main/com/example/security/MockUserFilter.kt

File: src/kotlin/main/com/example/security/MockUserFilter.kt
Status: Failed
Severity: N/A
Title: Analysis Failed
Description:
N/A
Proof of Concept:
N/A

---

Analysis File: src/kotlin/main/com/example/security/JwtFilter.kt

File: src/kotlin/main/com/example/service/AuthenticationService.kt
Status: Complete
Severity: High (8.5)
Title: Variable-time string comparison used for JWT cache checks
Description:
Variable-time string comparison functions are used to check JWTs against the cache.
This allows an attacker to discern the values of JWTs currently in the application cache.
Proof of Concept:
N/A

<next>

File: src/kotlin/main/com/example/service/AuthenticationService.kt
Status: Complete
Severity: Medium (5.0)
Title: Variable-time string comparison used for password hash checks
Description:
Variable-time string comparison functions are used for string comparison checks.
Proof of Concept: N/A

---

Analysis File: src/kotlin/main/com/example/controller/UserController.kt

File: src/kotlin/main/com/example/controller/UserController.kt
Status: Complete
Severity: High (7.0)
Title: Arbitrary user write without permission checks for profile updates
Description:
The current user's ID not is not checked or validated whenever updating a profile.

Proof of Concept:
For a user `userId`, perform `PUT /api/v1/users/{userId}` with a payload and you may update any
user's profile. Note that the `userId` is not checked as part of the query.

```
$ curl 'http://localhost:8080/api/v1/users/1234'
{"id": "1234", "firstName": "Johnathan", "lastName": "Doe"}
$ curl 'http://localhost:8080/api/v1/users/1234' -X PUT -H 'Content-Type: application/json' -d
{"id": "1234", "firstName": "Johnathan", "lastName": "pwned"}
$ curl 'http://localhost:8080/api/v1/users/1234'
{"id": "1234", "firstName": "Johnathan", "lastName": "pwned"}
```

---

"""

FILE_ANALYSIS_PROMPT = """
You may now begin analyzing your file. You have access to the read_file and list_directory tool calls.

Analysis File: """

FILE_VERIFY_TASK = PROMPT_BASE + '\n' + """
You have been assigned a bug report to verify. Your task is to confirm whether the
described vulnerability actually exists in the codebase.

Classify the verification as one of two types:
- "audit": The vulnerability can be confirmed by reading the code alone. Use this only
  whenever it is extremely difficult to create a proof-of-concept (i.e. cryptography flaws).
  Since false positives are costly, only use this type for cryptographic or difficult-to-
  confirm vulnerabilities.
- "poc": The vulnerability requires a working proof-of-concept to confirm it is exploitable
  (e.g., SQL injection, authentication bypass, XSS, SSRF, RCE). Use this when the bug
  depends on runtime data-flow or requires demonstration against a running service.

For "audit" findings, read the relevant source file(s) and confirm or refute the claim.
For "poc" findings, evaluate whether the provided proof-of-concept is technically sound
and correctly targets the described vulnerability path in the code. Write a corrected or
improved working PoC if the original is incomplete or incorrect.

You have access to the read_file and list_directory tools to read source code. You also have
a sandbox working directory pre-populated with bug_report.md (and verify_instructions.md if
applicable). Use write_file to create scripts or payloads in the sandbox, then run_command
to execute them.

Respond using exactly this format:

Verify: <bug title>
Type: "audit" | "poc"
Status: "success" | "failure"
Notes:
<one or more paragraphs explaining your conclusion>
WorkingPoC:
<runnable proof-of-concept code or steps, or N/A>

Examples:

---

Verify: IDOR on profile update endpoint allows arbitrary user modification
Type: poc
Status: success
Notes:
The UserController maps PUT /api/v1/users/{userId} directly to the service layer without checking
that the authenticated principal matches the path parameter. Any authenticated user can overwrite
another user's profile fields by substituting a different userId in the URL.

The curl commands below were executed against the staging environment. The first request confirms
the victim's original data, the second overwrites it as a different user, and the third confirms
the change persisted.
WorkingPoC:
# Authenticate as attacker (user 5678) and modify victim (user 1234)
TOKEN=$(curl -s -X POST https://staging.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"attacker@example.com","password":"password"}' | jq -r '.token')

curl -s https://staging.example.com/api/v1/users/1234 -H "Authorization: Bearer $TOKEN"
# {"id":"1234","firstName":"Johnathan","lastName":"Doe"}

curl -s -X PUT https://staging.example.com/api/v1/users/1234 \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"firstName":"Johnathan","lastName":"pwned"}'

curl -s https://staging.example.com/api/v1/users/1234 -H "Authorization: Bearer $TOKEN"
# {"id":"1234","firstName":"Johnathan","lastName":"pwned"}

---

Verify: MD5 used for password hashing in UserService
Type: audit
Status: success
Notes:
Confirmed by reading UserService.kt. The hashPassword method calls
MessageDigest.getInstance("MD5") and passes the raw password bytes directly with no salt.
MD5 is a broken cryptographic hash — it is trivially reversible via rainbow tables and
preimage attacks. No PoC is needed; the algorithm choice alone is the vulnerability.
WorkingPoC:
N/A

---

Verify: SQL injection in user search via lastName parameter
Type: poc
Status: failure
Notes:
The bug report claimed that the lastName query parameter is concatenated directly into a SQL
string in UserRepository. Reading the file shows that lastName is passed through a
JPA @Query with a named parameter binding (:lastName), which the framework treats as a
prepared statement. The input is never interpolated as raw SQL. Manual curl tests against
staging confirmed no anomalous behaviour — single quotes and UNION payloads were rejected
or returned empty result sets without errors.
WorkingPoC:
N/A

---

Verify: SQL injection via User ID
Type: poc
Status: failure
Notes:
The bug report claimed that the user ID parameter is concatenated directly into an SQL string
in UserRepository. Reading the file shows that this is correct, but the the User ID is cast to
an integer before concatenation. Therefore, there is no logical way to exploit this issue.
WorkingPoC:
N/A

"""

FILE_VERIFY_PROMPT = """\
Bug Title: {title}
Severity: {severity}
Primary File: {primary_file}

Description:
{description}

Proof of Concept:
{poc}

Verify: """


def _parse_bug_reports(content: str, primary_file: str) -> list[BugReport]:
    reports = []
    for block in content.split("<next>"):
        status_match = re.search(r"Status:\s*(\w+)", block)
        if not status_match or status_match.group(1).lower() == "failed":
            continue
        title_match = re.search(r"Title:\s*(.+)", block)
        if not title_match:
            continue
        severity_match = re.search(r"Severity:\s*\S+\s*\((\d+(?:\.\d+)?)\)", block)
        desc_match = re.search(r"Description:\s*\n(.*?)(?:Proof of Concept:|$)", block, re.DOTALL)
        poc_match = re.search(r"Proof of Concept:\s*\n?(.*?)$", block, re.DOTALL)
        reports.append(BugReport(
            title=title_match.group(1).strip(),
            severity=float(severity_match.group(1)) if severity_match else 0.0,
            primary_file=primary_file,
            description=desc_match.group(1).strip() if desc_match else "",
            poc=poc_match.group(1).strip() if poc_match else "",
            raw=block.strip(),
        ))
    return reports


def _parse_verify_result(content: str) -> tuple[str, str, str, str | None] | None:
    type_match = re.search(r"Type:\s*(audit|poc)", content, re.IGNORECASE)
    status_match = re.search(r"Status:\s*(success|failure)", content, re.IGNORECASE)
    notes_match = re.search(r"Notes:\s*\n(.*?)(?:WorkingPoC:|$)", content, re.DOTALL)
    poc_match = re.search(r"WorkingPoC:\s*\n?(.*?)$", content, re.DOTALL)
    if not type_match or not status_match:
        return None
    raw_poc = poc_match.group(1).strip() if poc_match else None
    working_poc = None if (not raw_poc or raw_poc.upper() == "N/A") else raw_poc
    return (
        type_match.group(1).lower(),
        status_match.group(1).lower(),
        notes_match.group(1).strip() if notes_match else "",
        working_poc,
    )


def verify(attempt: ReproAttempt, llm, src_path: Path, *, notes: str | None = None, verify_instructions: str | None = None) -> tuple[str, str, str, str | None] | None:
    system_prompt = _with_notes(FILE_VERIFY_TASK, notes)
    system_prompt = _with_verify_instructions(system_prompt, verify_instructions)
    system_message = SystemMessage(content=system_prompt)
    tool_call_id = str(uuid.uuid4())

    try:
        file_content = (src_path / attempt.primary_file).read_text()
    except Exception as e:
        file_content = f"Error reading file: {e}"

    prompt = FILE_VERIFY_PROMPT.format(
        title=attempt.title,
        severity=attempt.severity,
        primary_file=attempt.primary_file,
        description=attempt.description,
        poc=attempt.poc or "N/A",
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)
        (tmppath / "bug_report.md").write_text(
            f"# Bug Report\n\n"
            f"**Title:** {attempt.title}\n"
            f"**Severity:** {attempt.severity}\n"
            f"**Primary File:** {attempt.primary_file}\n\n"
            f"## Description\n{attempt.description}\n\n"
            f"## Proof of Concept\n{attempt.poc or 'N/A'}\n"
        )
        if verify_instructions:
            (tmppath / "verify_instructions.md").write_text(verify_instructions)

        agent = make_analysis_agent(llm, make_file_tools(src_path) + make_sandbox_tools(tmpdir))

        response = agent.invoke({"messages": [
            system_message,
            HumanMessage(content=prompt),
            AIMessage(content="", tool_calls=[{
                "id": tool_call_id,
                "name": "read_file",
                "args": {"path": attempt.primary_file},
            }]),
            ToolMessage(content=file_content, tool_call_id=tool_call_id),
        ]})

    last_message = response["messages"][-1]
    content = last_message.content
    if isinstance(content, list):
        content = " ".join(p["text"] for p in content if p.get("type") == "text")

    return content, _parse_verify_result(content)


def analysis(file: FileRanking, agent, src_path: Path, *, notes: str | None = None) -> list[BugReport]:
    system_message = SystemMessage(content=_with_notes(FILE_ANALYSIS_TASK, notes))
    tool_call_id = str(uuid.uuid4())

    try:
        file_content = (src_path / file.path).read_text()
    except Exception as e:
        file_content = f"Error reading file: {e}"

    response = agent.invoke({"messages": [
        system_message,
        HumanMessage(content=FILE_ANALYSIS_PROMPT + file.path),
        AIMessage(content="", tool_calls=[{
            "id": tool_call_id,
            "name": "read_file",
            "args": {"path": file.path},
        }]),
        ToolMessage(content=file_content, tool_call_id=tool_call_id),
    ]})

    last_message = response["messages"][-1]
    content = last_message.content
    if isinstance(content, list):
        content = " ".join(p["text"] for p in content if p.get("type") == "text")

    return _parse_bug_reports(content, file.path)


def _sync_files(state: State, src_path: Path, excludes: list[Path]) -> list[str]:
    src_files = set(list_tracked_files(src_path, excludes))
    db_paths = {f.path for f in state.get_file_rankings()}

    to_delete = sorted(db_paths - src_files)
    if to_delete:
        print(f"Deleting {len(to_delete)} file(s) from database...")
        state.delete_file_ranking(to_delete)

    return sorted(src_files - db_paths)


def _rank_phase(state: State, src_path: Path, args: Namespace, unranked: list[str]) -> None:
    if not unranked:
        return
    agent = make_analysis_agent(make_llm(args.provider, args.model), make_file_tools(src_path))
    print(f"Ranking {len(unranked)} new file(s)...")
    for path, score in rank_files(agent, unranked, src_path):
        state.insert_file_ranking(path, score)
        print(f"  {score:2.1f}  {path}")


_ANALYSIS_WORKERS = 6

def _analysis_phase(state: State, src_path: Path, args: Namespace, *, notes: str | None = None) -> None:
    if args.analysis_count <= 0:
        return

    # Collect distinct targets in memory without touching the DB.
    reserved: set[str] = set()
    targets: list[FileRanking] = []
    for _ in range(args.analysis_count):
        target = state.next_analysis_target(exclude=reserved)
        if target is None:
            break
        reserved.add(target.path)
        targets.append(target)

    if not targets:
        return

    agent = make_analysis_agent(make_llm(args.provider, args.model), make_file_tools(src_path))
    print(f"Analyzing {len(targets)} file(s) with {_ANALYSIS_WORKERS} workers...")

    with ThreadPoolExecutor(max_workers=_ANALYSIS_WORKERS) as executor:
        futures = {executor.submit(analysis, target, agent, src_path, notes=notes): target for target in targets}
        for future, target in futures.items():
            reports = future.result()
            state.increment_run_count(target.path)
            if reports:
                print(f"  {target.path}")
            for report in reports:
                bug_id = state.insert_bug_report(report)
                print(f"    [{bug_id}] {report.severity:.1f}  {report.title}")


_VERIFY_WORKERS = 6

def _verify_phase(state: State, src_path: Path, args: Namespace, *, notes: str | None = None, verify_instructions: str | None = None) -> None:
    if args.verify_count <= 0:
        return

    reserved: set[int] = set()
    targets: list[ReproAttempt] = []
    for _ in range(args.verify_count):
        batch = state.get_pending_repro_attempts(limit=1, exclude=reserved)
        if not batch:
            break
        attempt = batch[0]
        reserved.add(attempt.id)
        targets.append(attempt)

    if not targets:
        return

    llm = make_llm(args.provider, args.model)
    print(f"Verifying {len(targets)} bug report(s) with {_VERIFY_WORKERS} workers...")

    with ThreadPoolExecutor(max_workers=_VERIFY_WORKERS) as executor:
        futures = {
            executor.submit(verify, target, llm, src_path, notes=notes, verify_instructions=verify_instructions): target
            for target in targets
        }
        for future, target in futures.items():
            raw, parsed = future.result()
            if parsed is None:
                print(f"  [PARSE ERROR] [{target.bug_report_id}] {target.title}")
                state.update_repro_attempt(
                    target.id,
                    status="failure",
                    verification_type="unknown",
                    attempt_notes="Verify agent response could not be parsed.",
                    working_poc=None,
                    raw=raw,
                )
                continue
            verification_type, status, attempt_notes, working_poc = parsed
            icon = "+" if status == "success" else "-"
            print(f"  [{icon}] [{target.bug_report_id}] ({verification_type}) {target.title}")
            state.update_repro_attempt(
                target.id,
                status=status,
                verification_type=verification_type,
                attempt_notes=attempt_notes,
                working_poc=working_poc,
                raw=raw,
            )


def run_harness(args: Namespace) -> None:
    src_path = Path(args.src).expanduser()
    print(f"Source to examine: {src_path}")

    bugs = Path(args.bugs).expanduser()
    bugs.mkdir(parents=True, exist_ok=True)
    print(f"Analysis storage: {bugs}")

    project_notes = _load_project_notes(bugs)
    if project_notes:
        print(f"Project notes loaded from: {bugs / 'NOTES.md'}")

    verify_instructions = _load_verify_instructions(bugs)
    if verify_instructions:
        print(f"Verify instructions loaded from: {bugs / 'VERIFY.md'}")

    state = State(src_path=str(src_path), bugs_path=str(bugs))
    excludes = [Path(e) for e in args.excludes]

    unranked = _sync_files(state, src_path, excludes)

    if args.dry_run:
        return

    _rank_phase(state, src_path, args, unranked)
    _analysis_phase(state, src_path, args, notes=project_notes)
    _verify_phase(state, src_path, args, notes=project_notes, verify_instructions=verify_instructions)


def rank_files(agent, files: list[str], src_path: Path) -> Generator[tuple[str, float], None, None]:
    system_message = SystemMessage(content=FILE_RANK_TASK)
    q: Queue[tuple[str, float]] = Queue()

    def rank_one(path: str) -> None:
        tool_call_id = str(uuid.uuid4())
        try:
            file_content = (src_path / path).read_text()
        except Exception as e:
            file_content = f"Error reading file: {e}"
        response = agent.invoke({"messages": [
            system_message,
            HumanMessage(content=f"File: {path}\nScore:"),
            AIMessage(content="", tool_calls=[{
                "id": tool_call_id,
                "name": "read_file",
                "args": {"path": path},
            }]),
            ToolMessage(content=file_content, tool_call_id=tool_call_id),
        ]})
        last_message = response["messages"][-1]
        content = last_message.content
        if isinstance(content, list):
            content = " ".join(p["text"] for p in content if p.get("type") == "text")
        match = re.search(r"Score:\s*\*{0,2}(\d+(?:\.\d+)?)\*{0,2}", content)
        if match:
            q.put((path, float(match.group(1))))
        else:
            print(f"Invalid score for {path}: <<{content}>>")
            q.put((path, 0.0))

    with ThreadPoolExecutor(max_workers=8) as executor:
        for path in files:
            executor.submit(rank_one, path)
        for _ in files:
            yield q.get()

def list_tracked_files(repo_path: str | Path, excludes: list[Path] | None = None) -> list[str]:
    repo_path = Path(repo_path)
    excludes = excludes or []
    exclude_names = {e.name for e in excludes if not e.parts[1:]}

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        check=True,
        shell=False,
    )

    return [
        p for p in result.stdout.splitlines()
        if Path(p).suffix.lower() not in SKIP_EXTENSIONS
        and Path(p).name not in BLOCKED_NAMES
        and not any(part in BLOCKED_DIRS for part in Path(p).parts)
        and not any(Path(p).is_relative_to(e) for e in excludes)
        and Path(p).name not in exclude_names
    ]
