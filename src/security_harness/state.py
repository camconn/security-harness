import sqlite3
from dataclasses import dataclass
from pathlib import Path

@dataclass
class FileRanking:
    path: str
    score: float
    run_count: int

@dataclass
class BugReport:
    title: str
    severity: float
    primary_file: str
    description: str
    poc: str
    raw: str

@dataclass
class ReproAttempt:
    id: int
    bug_report_id: int
    status: str
    poc: str | None
    # Joined from bug_report
    title: str
    description: str
    primary_file: str
    severity: float

class State:
    src_path: str
    bugs_path: str

    _sqlite_conn: sqlite3.Connection | None
    _sqlite_name = "security_harness.db"

    def __init__(self, src_path: str, bugs_path: str):
        self.src_path = src_path
        self.bugs_path = bugs_path
        self._sqlite_conn = None

    def setup_database(self):
        if self._sqlite_conn is None:
            sqlite_file = str(Path(self.bugs_path) / self._sqlite_name)
            self._sqlite_conn = sqlite3.connect(sqlite_file)
        else:
            # Already set up the database
            return

        cur = self._sqlite_conn.cursor()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS project_file (
            path          TEXT PRIMARY KEY,
            score         DOUBLE NOT NULL,
            run_count     INTEGER NOT NULL DEFAULT 0
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS bug_report(
            id              INTEGER PRIMARY KEY,
            title           TEXT NOT NULL,
            found_at        TEXT NOT NULL,
            severity        DOUBLE NOT NULL,
            primary_file    TEXT NOT NULL REFERENCES project_file(path),
            description     TEXT NOT NULL,
            raw             TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS bug_repro_attempt(
            id              INTEGER PRIMARY KEY,
            bug_report_id   INTEGER NOT NULL REFERENCES bug_report(id),
            status          TEXT NOT NULL, -- 'pending', 'success', 'failure'
            reproduced_on   TEXT,
            poc             TEXT
        )
        """)

        for col_sql in [
            "ALTER TABLE bug_repro_attempt ADD COLUMN attempted_at      TEXT",
            "ALTER TABLE bug_repro_attempt ADD COLUMN attempt_notes     TEXT",
            "ALTER TABLE bug_repro_attempt ADD COLUMN verification_type TEXT",
            "ALTER TABLE bug_repro_attempt ADD COLUMN working_poc       TEXT",
            "ALTER TABLE bug_repro_attempt ADD COLUMN raw               TEXT",
        ]:
            try:
                cur.execute(col_sql)
            except sqlite3.OperationalError:
                pass  # column already exists

        self._sqlite_conn.commit()

    def get_file_rankings(self) -> list[FileRanking]:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute("SELECT path, score, run_count FROM project_file ORDER BY score DESC")
        return [FileRanking(path=row[0], score=row[1], run_count=row[2]) for row in cur.fetchall()]

    def insert_file_ranking(self, path: str, score: float) -> None:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute(
            """
            INSERT INTO project_file (path, score, run_count)
            VALUES (?, ?, 0)
            ON CONFLICT(path) DO UPDATE SET
                score = excluded.score,
                run_count = project_file.run_count + 1
            """,
            (path, score),
        )
        self._sqlite_conn.commit()

    def increment_run_count(self, path: str) -> None:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute(
            """
            UPDATE project_file
            SET run_count = run_count + 1
            WHERE path = ?
            """,
            (path,),
        )
        self._sqlite_conn.commit()

    def next_analysis_target(self, exclude: set[str] | None = None) -> "FileRanking | None":
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        excluded = exclude or set()
        # TODO: Handle possible SQLi here
        exclude_clause = f"AND path NOT IN ({','.join('?' * len(excluded))})" if excluded else ""
        cur.execute(f"""
            SELECT path, score, run_count
            FROM project_file
            WHERE score > 0
            {exclude_clause}
            ORDER BY score / (run_count + 1) DESC
            LIMIT 1
        """, list(excluded))
        row = cur.fetchone()
        return FileRanking(path=row[0], score=row[1], run_count=row[2]) if row else None

    def insert_bug_report(self, report: BugReport) -> int:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute(
            """
            INSERT INTO bug_report (title, found_at, severity, primary_file, description, raw)
            VALUES (?, datetime('now'), ?, ?, ?, ?)
            """,
            (report.title, report.severity, report.primary_file, report.description, report.raw),
        )
        bug_id = cur.lastrowid
        cur.execute(
            """
            INSERT INTO bug_repro_attempt (bug_report_id, status, poc)
            VALUES (?, 'pending', ?)
            """,
            (bug_id, report.poc),
        )
        self._sqlite_conn.commit()
        return bug_id

    def get_pending_repro_attempts(
        self,
        limit: int,
        exclude: set[int] | None = None,
    ) -> list[ReproAttempt]:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        excluded = exclude or set()
        exclude_clause = (
            f"AND a.id NOT IN ({','.join('?' * len(excluded))})"
            if excluded else ""
        )
        cur.execute(f"""
            SELECT a.id, a.bug_report_id, a.status, a.poc,
                   r.title, r.description, r.primary_file, r.severity
            FROM bug_repro_attempt a
            JOIN bug_report r ON r.id = a.bug_report_id
            WHERE a.status = 'pending'
            {exclude_clause}
            ORDER BY r.severity DESC, a.id ASC
            LIMIT ?
        """, [*list(excluded), limit])
        return [
            ReproAttempt(
                id=row[0], bug_report_id=row[1], status=row[2], poc=row[3],
                title=row[4], description=row[5], primary_file=row[6], severity=row[7],
            )
            for row in cur.fetchall()
        ]

    def update_repro_attempt(
        self,
        attempt_id: int,
        *,
        status: str,
        verification_type: str,
        attempt_notes: str,
        working_poc: str | None,
        raw: str | None,
    ) -> None:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute(
            """
            UPDATE bug_repro_attempt
            SET status            = ?,
                attempted_at      = datetime('now'),
                reproduced_on     = CASE WHEN ? = 'success' THEN datetime('now') ELSE reproduced_on END,
                attempt_notes     = ?,
                verification_type = ?,
                working_poc       = ?,
                raw               = ?
            WHERE id = ?
            """,
            (status, status, attempt_notes, verification_type, working_poc, raw, attempt_id),
        )
        self._sqlite_conn.commit()

    def get_canonical_bug_reports(self) -> list[tuple[int, "BugReport"]]:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute("SELECT id, title, severity, primary_file, description FROM bug_report")
        return [
            (row[0], BugReport(title=row[1], severity=row[2], primary_file=row[3], description=row[4], poc="", raw=""))
            for row in cur.fetchall()
        ]

    def delete_file_ranking(self, path: list[str]) -> None:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.executemany("DELETE FROM project_file WHERE path = ?", [(p,) for p in path])
        self._sqlite_conn.commit()
