#!/usr/bin/env python3
# crun - OCI runtime written in C
#
# Copyright (C) 2017, 2018, 2019 Giuseppe Scrivano <giuseppe@scrivano.org>
# crun is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# crun is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with crun.  If not, see <http://www.gnu.org/licenses/>.

"""
Run tests in multiple environments for comprehensive coverage.

This script runs the test suite multiple times in different environments
to maximize code coverage. It requires root privileges.

Usage: ./tests/run_coverage_multi_env.py

The script will:
1. Run tests as root with cgroupfs cgroup manager
2. Run tests as root with systemd cgroup manager (if available)
3. Run tests in a user namespace (simulated rootless via unshare)

Coverage data accumulates across all runs (lcov merges .gcda files).
"""

import glob
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

# Coverage output directory - can be overridden via COVERAGE_OUT environment variable
COVERAGE_OUT = os.environ.get('COVERAGE_OUT', 'docs/coverage')


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    NC = '\033[0m'


def log_info(msg):
    print(f"{Colors.GREEN}[INFO]{Colors.NC} {msg}")


def log_warn(msg):
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {msg}")


def log_error(msg):
    print(f"{Colors.RED}[ERROR]{Colors.NC} {msg}")


def run_command(cmd, env=None, check=False):
    """Run a command and return success status."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    result = subprocess.run(cmd, env=merged_env, shell=isinstance(cmd, str))
    return result.returncode == 0


def command_exists(cmd):
    """Check if a command exists in PATH."""
    return shutil.which(cmd) is not None


def get_make_jobs():
    """Get the -j flag value from MAKEFLAGS or default to CPU count."""
    makeflags = os.environ.get('MAKEFLAGS', '')

    # Try to extract -jN from MAKEFLAGS
    # Handles formats like: -j8, -j 8, --jobs=8, --jobs 8
    match = re.search(r'-j\s*(\d+)|--jobs[=\s]+(\d+)', makeflags)
    if match:
        jobs = match.group(1) or match.group(2)
        return f'-j{jobs}'

    # Check for jobserver mode (indicates parallel make but we can't reuse it)
    # Fall back to CPU count
    nproc = os.cpu_count() or 1
    return f'-j{nproc}'


def clean_test_artifacts():
    """Remove test artifacts that may cause permission issues across environments."""
    patterns = [
        'libocispec/**/*.log',
        'libocispec/**/*.trs',
        'tests/*.log',
        'tests/*.trs',
        'test-suite.log',
    ]
    removed = 0
    for pattern in patterns:
        for f in glob.glob(pattern, recursive=True):
            try:
                if os.path.isfile(f):
                    os.remove(f)
                    removed += 1
            except OSError as e:
                log_warn(f"Failed to remove {f}: {e}")
    if removed > 0:
        log_info(f"Cleaned up {removed} test artifact(s)")


def chown_recursive(path, uid, gid):
    """Recursively change ownership of all files and directories."""
    count = 0
    for root, dirs, files in os.walk(path):
        # Skip .git directory
        if '.git' in dirs:
            dirs.remove('.git')
        try:
            os.lchown(root, uid, gid)
            count += 1
        except OSError as e:
            log_warn(f"Failed to chown {root}: {e}")
        for f in files:
            try:
                os.lchown(os.path.join(root, f), uid, gid)
                count += 1
            except OSError:
                pass
    log_info(f"Changed ownership of {count} items")


def run_environment(name, env_vars, cmd):
    """Run tests in a specific environment. Exit on failure."""
    clean_test_artifacts()
    log_info(f"=== {name} ===")

    if run_command(cmd, env=env_vars):
        log_info(f"{name} completed successfully")
    else:
        log_error(f"{name} FAILED")
        sys.exit(1)


def main():
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent

    if os.geteuid() != 0:
        log_error("This script must be run as root")
        sys.exit(1)

    os.chdir(project_root)

    make_jobs = get_make_jobs()

    log_info("Resetting coverage counters...")
    run_command(['make', 'coverage-reset'])

    run_environment(
        "Environment 1: Root (uid=0) with cgroupfs",
        {'CGROUP_MANAGER': 'cgroupfs'},
        ['make', make_jobs, 'check-TESTS']
    )

    if Path('/run/systemd/system').exists():
        run_environment(
            "Environment 2: Root (uid=0) with systemd cgroup manager",
            {'CGROUP_MANAGER': 'systemd'},
            ['make', make_jobs, 'check-TESTS']
        )
    else:
        log_warn("Systemd not running, skipping environment 2")

    # Get the owner of the current directory for proper uid mapping
    dir_stat = os.stat('.')
    dir_uid = dir_stat.st_uid
    dir_gid = dir_stat.st_gid

    # Chown all files to directory owner before user namespace environments
    # This ensures files created by root are accessible in the user namespace
    log_info(f"Changing ownership of all files to {dir_uid}:{dir_gid}...")
    chown_recursive('.', dir_uid, dir_gid)

    run_environment(
        "Environment 3: User namespace (rootless simulation)",
        {'CGROUP_MANAGER': 'cgroupfs'},
        ['unshare', '--user', f'--map-users=0:{dir_uid}:1', f'--map-groups=0:{dir_gid}:1',
         '--setuid=0', '--setgid=0', '--mount', '--pid', '--fork', '--mount-proc',
         'sh', '-c', f'unset NOTIFY_SOCKET; CGROUP_MANAGER=cgroupfs make {make_jobs} check-TESTS']
    )

    # Generate combined coverage report
    log_info("=== Generating combined coverage report ===")

    if command_exists('lcov') and command_exists('genhtml'):
        log_info("Generating coverage report with lcov...")

        lcov_ignore = 'unused,empty'
        genhtml_ignore = 'unused,unmapped,empty'

        # Capture coverage data
        run_command([
            'lcov', '--capture', '--directory', '.',
            '--output-file', 'coverage.info', '--ignore-errors', lcov_ignore
        ])

        # Remove system headers
        run_command([
            'lcov', '--remove', 'coverage.info', '/usr/*',
            '--output-file', 'coverage.info', '--ignore-errors', lcov_ignore
        ])

        # Remove libocispec
        run_command([
            'lcov', '--remove', 'coverage.info', '*/libocispec/*',
            '--output-file', 'coverage.info', '--ignore-errors', lcov_ignore
        ])

        # Remove test files
        run_command([
            'lcov', '--remove', 'coverage.info', '*/tests/test_*.py*',
            '--output-file', 'coverage.info', '--ignore-errors', lcov_ignore
        ])

        # Remove init test binary
        run_command([
            'lcov', '--remove', 'coverage.info', '*/tests/init*',
            '--output-file', 'coverage.info', '--ignore-errors', lcov_ignore
        ])

        # Generate HTML report
        run_command([
            'genhtml', 'coverage.info', '--output-directory', COVERAGE_OUT,
            '--ignore-errors', genhtml_ignore
        ])

        log_info("Coverage report generated successfully")
        log_info(f"View the report at: {project_root}/{COVERAGE_OUT}/index.html")

    elif command_exists('gcovr'):
        log_info("Generating coverage report with gcovr...")
        run_command([
            'gcovr', '--html', '--html-details', '-o', 'coverage.html',
            '--exclude', '/usr/.*', '--exclude', '.*/libocispec/.*',
            '--exclude', '.*/tests/test_.*\\.py.*', '--exclude', '.*/tests/init.*'
        ])
        log_info("Coverage report generated in coverage.html")
    else:
        log_error("Neither lcov nor gcovr found. Install one to generate HTML reports.")
        log_info("You can still view raw coverage with: gcov src/libcrun/*.c")

    # Summary
    print()
    log_info("=== All environments completed successfully ===")

    return 0


if __name__ == '__main__':
    sys.exit(main())
