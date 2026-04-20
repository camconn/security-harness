from security_harness.harness import _parse_bug_reports, _parse_verify_result, _parse_dedup_result


# --- _parse_bug_reports ---

def test_parse_single_bug():
    content = """\
File: src/auth.py
Status: Complete
Severity: High (8.5)
Title: SQL Injection in login endpoint
Description:
The login query concatenates user input directly.
Proof of Concept:
curl -X POST /login -d "user=' OR '1'='1"
"""
    reports = _parse_bug_reports(content, "src/auth.py")
    assert len(reports) == 1
    r = reports[0]
    assert r.title == "SQL Injection in login endpoint"
    assert r.severity == 8.5
    assert r.primary_file == "src/auth.py"
    assert "concatenates user input" in r.description
    assert "curl" in r.poc


def test_parse_multiple_bugs():
    content = """\
File: src/auth.py
Status: Complete
Severity: High (8.5)
Title: First Bug
Description:
First description.
Proof of Concept:
PoC one.
<next>
File: src/auth.py
Status: Complete
Severity: Medium (5.0)
Title: Second Bug
Description:
Second description.
Proof of Concept:
PoC two.
"""
    reports = _parse_bug_reports(content, "src/auth.py")
    assert len(reports) == 2
    assert reports[0].title == "First Bug"
    assert reports[1].title == "Second Bug"
    assert reports[1].severity == 5.0


def test_parse_failed_status_skipped():
    content = """\
File: src/auth.py
Status: Failed
Severity: N/A
Title: Analysis Failed
Description:
N/A
Proof of Concept:
N/A
"""
    reports = _parse_bug_reports(content, "src/auth.py")
    assert reports == []


def test_parse_empty_content():
    assert _parse_bug_reports("", "src/auth.py") == []


def test_parse_no_bug_markers():
    assert _parse_bug_reports("No vulnerabilities found in this file.", "src/foo.py") == []


def test_parse_quoted_status_complete():
    """LLM may follow the format spec literally and quote the status value."""
    content = """\
File: ayylmao.txt
Status: "Complete"
Severity: Medium (5.9)
Title: Quotes in the "Status" field break the parser
Description:
This reproduction report breaks the report validation parser.

Proof of Concept:
Put "quotes" around the status in the reproduction report, and it dies!

"""
    reports = _parse_bug_reports(content, "scripts/fetch-creds.sh")
    assert len(reports) == 1
    assert reports[0].title == 'Quotes in the "Status" field break the parser'
    assert reports[0].severity == 5.9


def test_parse_missing_severity_defaults_to_zero():
    content = """\
Status: Complete
Title: No Severity Bug
Description:
Something bad.
Proof of Concept:
N/A
"""
    reports = _parse_bug_reports(content, "src/foo.py")
    assert len(reports) == 1
    assert reports[0].severity == 0.0


def test_parse_primary_file_from_argument():
    content = """\
Status: Complete
Severity: Low (2.0)
Title: Minor Issue
Description:
Details.
Proof of Concept:
N/A
"""
    reports = _parse_bug_reports(content, "src/specific/file.py")
    assert reports[0].primary_file == "src/specific/file.py"


# --- _parse_verify_result ---

def test_verify_poc_success():
    content = """\
Verify: SQL Injection in login
Type: poc
Status: success
Notes:
Confirmed — the query is directly concatenated.
WorkingPoC:
curl -X POST /login -d "user=admin'--"
"""
    result = _parse_verify_result(content)
    assert result is not None
    vtype, status, notes, working_poc = result
    assert vtype == "poc"
    assert status == "success"
    assert "concatenated" in notes
    assert working_poc is not None
    assert "curl" in working_poc


def test_verify_audit_failure():
    content = """\
Type: audit
Status: failure
Notes:
The code actually uses parameterized queries.
WorkingPoC:
N/A
"""
    result = _parse_verify_result(content)
    assert result is not None
    vtype, status, notes, working_poc = result
    assert vtype == "audit"
    assert status == "failure"
    assert working_poc is None


def test_verify_working_poc_na_becomes_none():
    content = """\
Type: poc
Status: failure
Notes:
Not exploitable.
WorkingPoC:
N/A
"""
    result = _parse_verify_result(content)
    assert result is not None
    _, _, _, working_poc = result
    assert working_poc is None


def test_verify_missing_type_returns_none():
    content = """\
Status: success
Notes:
Something.
WorkingPoC:
N/A
"""
    assert _parse_verify_result(content) is None


def test_verify_missing_status_returns_none():
    content = """\
Type: poc
Notes:
Something.
WorkingPoC:
N/A
"""
    assert _parse_verify_result(content) is None


def test_verify_empty_content_returns_none():
    assert _parse_verify_result("") is None


# --- _parse_dedup_result ---

def test_dedup_number_match():
    assert _parse_dedup_result("Duplicate: 3\nReasoning: Same root cause.") == 3


def test_dedup_none():
    assert _parse_dedup_result("Duplicate: none\nReasoning: Different attack surfaces.") is None


def test_dedup_case_insensitive():
    assert _parse_dedup_result("Duplicate: 1") == 1
    assert _parse_dedup_result("Duplicate: None") is None
    assert _parse_dedup_result("Duplicate: NONE") is None


def test_dedup_empty_returns_none():
    assert _parse_dedup_result("") is None


def test_dedup_no_marker_returns_none():
    assert _parse_dedup_result("These bugs look similar but are distinct issues.") is None
