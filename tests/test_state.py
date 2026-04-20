import pytest
from security_harness.state import BugReport, State


def make_state(tmp_path) -> State:
    state = State(src_path=str(tmp_path), bugs_path=str(tmp_path))
    return state


def sample_report(primary_file: str = "src/auth.py") -> BugReport:
    return BugReport(
        title="SQL Injection",
        severity=8.5,
        primary_file=primary_file,
        description="User input concatenated into query.",
        poc="curl -X POST /login -d \"user=' OR '1'='1\"",
        raw="raw content",
    )


# --- File rankings ---

def test_insert_and_get_file_ranking(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    rankings = state.get_file_rankings()
    assert len(rankings) == 1
    assert rankings[0].path == "src/auth.py"
    assert rankings[0].score == 9.0
    assert rankings[0].run_count == 0


def test_get_file_rankings_ordered_by_score(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/low.py", 2.0)
    state.insert_file_ranking("src/high.py", 9.0)
    state.insert_file_ranking("src/mid.py", 5.0)
    rankings = state.get_file_rankings()
    scores = [r.score for r in rankings]
    assert scores == sorted(scores, reverse=True)


def test_upsert_same_path_updates_score(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 5.0)
    state.insert_file_ranking("src/auth.py", 9.0)
    rankings = state.get_file_rankings()
    assert len(rankings) == 1
    assert rankings[0].score == 9.0


def test_increment_run_count(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 7.0)
    state.increment_run_count("src/auth.py")
    rankings = state.get_file_rankings()
    assert rankings[0].run_count == 1


def test_next_analysis_target_returns_highest_priority(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/low.py", 2.0)
    state.insert_file_ranking("src/high.py", 8.0)
    target = state.next_analysis_target()
    assert target is not None
    assert target.path == "src/high.py"


def test_next_analysis_target_excludes_path(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/high.py", 8.0)
    state.insert_file_ranking("src/low.py", 2.0)
    target = state.next_analysis_target(exclude={"src/high.py"})
    assert target is not None
    assert target.path == "src/low.py"


def test_next_analysis_target_empty_db_returns_none(tmp_path):
    state = make_state(tmp_path)
    assert state.next_analysis_target() is None


def test_next_analysis_target_zero_score_excluded(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/zero.py", 0.0)
    assert state.next_analysis_target() is None


def test_delete_file_ranking(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 7.0)
    state.insert_file_ranking("src/other.py", 3.0)
    state.delete_file_ranking(["src/auth.py"])
    rankings = state.get_file_rankings()
    assert len(rankings) == 1
    assert rankings[0].path == "src/other.py"


def test_delete_file_ranking_nonexistent_is_noop(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 7.0)
    state.delete_file_ranking(["src/does_not_exist.py"])
    assert len(state.get_file_rankings()) == 1


# --- Bug reports ---

def test_insert_and_get_bug_report(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    report = sample_report()
    bug_id = state.insert_bug_report(report)
    assert isinstance(bug_id, int)
    canonical = state.get_canonical_bug_reports()
    assert len(canonical) == 1
    assert canonical[0][0] == bug_id
    assert canonical[0][1].title == "SQL Injection"


def test_insert_bug_report_creates_pending_attempt(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    state.insert_bug_report(sample_report())
    attempts = state.get_pending_repro_attempts(limit=10)
    assert len(attempts) == 1
    assert attempts[0].status == "pending"


def test_multiple_bug_reports(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    state.insert_bug_report(sample_report())
    state.insert_bug_report(BugReport(
        title="XSS in comments", severity=6.0,
        primary_file="src/auth.py", description="Unescaped output.",
        poc="<script>alert(1)</script>", raw="raw",
    ))
    assert len(state.get_canonical_bug_reports()) == 2


# --- Verification ---

def test_get_pending_repro_attempts_sorted_by_severity(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    low = BugReport("Low Sev", 2.0, "src/auth.py", "desc", "poc", "raw")
    high = BugReport("High Sev", 9.0, "src/auth.py", "desc", "poc", "raw")
    state.insert_bug_report(low)
    state.insert_bug_report(high)
    attempts = state.get_pending_repro_attempts(limit=10)
    assert attempts[0].title == "High Sev"
    assert attempts[1].title == "Low Sev"


def test_get_pending_repro_attempts_limit(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    for i in range(5):
        state.insert_bug_report(BugReport(f"Bug {i}", float(i), "src/auth.py", "d", "p", "r"))
    attempts = state.get_pending_repro_attempts(limit=2)
    assert len(attempts) == 2


def test_get_pending_repro_attempts_exclude(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    state.insert_bug_report(sample_report())
    attempts = state.get_pending_repro_attempts(limit=10)
    attempt_id = attempts[0].id
    result = state.get_pending_repro_attempts(limit=10, exclude={attempt_id})
    assert all(a.id != attempt_id for a in result)


def test_update_repro_attempt(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    state.insert_bug_report(sample_report())
    attempts = state.get_pending_repro_attempts(limit=1)
    attempt_id = attempts[0].id
    state.update_repro_attempt(
        attempt_id,
        status="success",
        verification_type="poc",
        attempt_notes="Exploitable.",
        working_poc="curl ...",
        raw="raw output",
    )
    pending = state.get_pending_repro_attempts(limit=10)
    assert all(a.id != attempt_id for a in pending)


def test_update_repro_attempt_failure(tmp_path):
    state = make_state(tmp_path)
    state.insert_file_ranking("src/auth.py", 9.0)
    state.insert_bug_report(sample_report())
    attempts = state.get_pending_repro_attempts(limit=1)
    attempt_id = attempts[0].id
    state.update_repro_attempt(
        attempt_id,
        status="failure",
        verification_type="audit",
        attempt_notes="Not reproducible.",
        working_poc=None,
        raw="raw",
    )
    pending = state.get_pending_repro_attempts(limit=10)
    assert len(pending) == 0
