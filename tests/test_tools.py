from security_harness.tools.files import make_file_tools


def get_tools(sandbox):
    tools = make_file_tools(sandbox)
    read_file = next(t for t in tools if t.name == "read_file")
    list_directory = next(t for t in tools if t.name == "list_directory")
    return read_file, list_directory


# --- read_file ---

def test_read_file_returns_content(tmp_path):
    (tmp_path / "hello.txt").write_text("hello world")
    read_file, _ = get_tools(tmp_path)
    result = read_file.invoke({"path": "hello.txt"})
    assert result == "hello world"


def test_read_file_path_traversal_blocked(tmp_path):
    read_file, _ = get_tools(tmp_path)
    result = read_file.invoke({"path": "../../etc/passwd"})
    assert result.startswith("Error:")


def test_read_file_blocked_name(tmp_path):
    (tmp_path / ".env").write_text("SECRET=abc")
    read_file, _ = get_tools(tmp_path)
    result = read_file.invoke({"path": ".env"})
    assert result.startswith("Error:")


def test_read_file_nonexistent_returns_error(tmp_path):
    read_file, _ = get_tools(tmp_path)
    result = read_file.invoke({"path": "does_not_exist.txt"})
    assert result.startswith("Error:")


def test_read_file_blocked_dir(tmp_path):
    idea_dir = tmp_path / ".idea"
    idea_dir.mkdir()
    (idea_dir / "workspace.xml").write_text("<project/>")
    read_file, _ = get_tools(tmp_path)
    result = read_file.invoke({"path": ".idea/workspace.xml"})
    assert result.startswith("Error:")


def test_read_file_nested_path(tmp_path):
    nested = tmp_path / "src" / "utils"
    nested.mkdir(parents=True)
    (nested / "helper.py").write_text("def helper(): pass")
    read_file, _ = get_tools(tmp_path)
    result = read_file.invoke({"path": "src/utils/helper.py"})
    assert "def helper" in result


# --- list_directory ---

def test_list_directory_lists_files(tmp_path):
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    _, list_directory = get_tools(tmp_path)
    result = list_directory.invoke({"path": "."})
    assert "a.txt" in result
    assert "b.txt" in result


def test_list_directory_empty_dir(tmp_path):
    _, list_directory = get_tools(tmp_path)
    result = list_directory.invoke({"path": "."})
    assert result == ""


def test_list_directory_path_traversal_blocked(tmp_path):
    _, list_directory = get_tools(tmp_path)
    result = list_directory.invoke({"path": "../../etc"})
    assert result.startswith("Error:")


def test_list_directory_blocked_dir(tmp_path):
    (tmp_path / ".idea").mkdir()
    _, list_directory = get_tools(tmp_path)
    result = list_directory.invoke({"path": ".idea"})
    assert result.startswith("Error:")


def test_list_directory_excludes_blocked_entries(tmp_path):
    (tmp_path / "safe.py").write_text("")
    (tmp_path / ".env").write_text("SECRET=abc")
    _, list_directory = get_tools(tmp_path)
    result = list_directory.invoke({"path": "."})
    assert "safe.py" in result
    assert ".env" not in result


def test_list_directory_nonexistent_returns_error(tmp_path):
    _, list_directory = get_tools(tmp_path)
    result = list_directory.invoke({"path": "no_such_dir"})
    assert result.startswith("Error:")
