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
        CREATE TABLE IF NOT EXISTS project_files (
            path          TEXT PRIMARY KEY,
            score         DOUBLE NOT NULL,
            run_count     INTEGER NOT NULL DEFAULT 0
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS bug_reports(
            id              INTEGER PRIMARY KEY,
            title           TEXT NOT NULL,
            found_at        TEXT NOT NULL,
            severity        DOUBLE NOT NULL,
            primary_file    TEXT NOT NULL REFERENCES project_files(path),
            description     TEXT NOT NULL
        )
        """)

        cur.execute("""
        CREATE TABLE IF NOT EXISTS bug_repro_attempts(
            id              INTEGER PRIMARY KEY,
            bug_report_id   INTEGER NOT NULL REFERENCES bug_reports(id),
            status          TEXT NOT NULL, -- 'pending', 'success', 'failure'
            reproduced_on   TEXT,
            poc             TEXT
        )
        """)

        self._sqlite_conn.commit()

    def get_file_rankings(self) -> list[FileRanking]:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute("SELECT path, score, run_count FROM project_files ORDER BY score DESC")
        return [FileRanking(path=row[0], score=row[1], run_count=row[2]) for row in cur.fetchall()]

    def insert_file_ranking(self, path: str, score: float) -> None:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute(
            """
            INSERT INTO project_files (path, score, run_count)
            VALUES (?, ?, 0)
            ON CONFLICT(path) DO UPDATE SET
                score = excluded.score,
                run_count = project_files.run_count + 1
            """,
            (path, score),
        )
        self._sqlite_conn.commit()

    def increment_run_count(self, path: str) -> None:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute(
            """
            UPDATE project_files
            SET run_count = run_count + 1
            WHERE path = ?
            """,
            (path,),
        )
        self._sqlite_conn.commit()

    def next_analysis_target(self) -> "FileRanking | None":
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute("""
            SELECT path, score, run_count
            FROM project_files
            WHERE score > 0
            ORDER BY score / (run_count + 1) DESC
            LIMIT 1
        """)
        row = cur.fetchone()
        return FileRanking(path=row[0], score=row[1], run_count=row[2]) if row else None

    def insert_bug_report(self, report: BugReport) -> int:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.execute(
            """
            INSERT INTO bug_reports (title, found_at, severity, primary_file, description)
            VALUES (?, datetime('now'), ?, ?, ?)
            """,
            (report.title, report.severity, report.primary_file, report.description),
        )
        bug_id = cur.lastrowid
        cur.execute(
            """
            INSERT INTO bug_repro_attempts (bug_report_id, status, poc)
            VALUES (?, 'pending', ?)
            """,
            (bug_id, report.poc),
        )
        self._sqlite_conn.commit()
        return bug_id

    def delete_file_ranking(self, path: list[str]) -> None:
        self.setup_database()
        cur = self._sqlite_conn.cursor()
        cur.executemany("DELETE FROM project_files WHERE path = ?", [(p,) for p in path])
        self._sqlite_conn.commit()
