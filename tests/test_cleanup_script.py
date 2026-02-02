"""
Tests for cleanup_files.py (cron entry script).
Runs the script in a subprocess with a temp dir and empty db to cover main block and exception path.
"""
import pytest
import os
import sys
import subprocess
import tempfile
import sqlite3


def test_cleanup_script_main_block_runs_successfully():
    """Running cleanup_files.py as __main__ runs init_db and cleanup_old_files without error."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    script_path = os.path.join(project_root, "cleanup_files.py")
    with tempfile.TemporaryDirectory() as tmpdir:
        # Use a clean dir so main uses xlsvc.db in cwd; init_db will create it
        result = subprocess.run(
            [sys.executable, script_path],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"stdout: {result.stdout}\nstderr: {result.stderr}"
        assert "Starting file cleanup" in result.stdout or "Cleanup completed" in result.stdout


def test_cleanup_script_exception_path():
    """When main import fails, script prints ERROR and exits with 1."""
    import shutil
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    src_script = os.path.join(project_root, "cleanup_files.py")
    with tempfile.TemporaryDirectory() as tmpdir:
        script_in_tmp = os.path.join(tmpdir, "cleanup_files.py")
        shutil.copy(src_script, script_in_tmp)
        fake_main = os.path.join(tmpdir, "main.py")
        with open(fake_main, "w") as f:
            f.write("raise RuntimeError('mock import failure')\n")
        # Script adds its dir (tmpdir) to path, so it will import our fake main
        result = subprocess.run(
            [sys.executable, script_in_tmp],
            cwd=tmpdir,
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 1
        assert "ERROR:" in result.stdout
        assert "mock import failure" in result.stdout
