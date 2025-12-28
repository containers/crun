# AGENTS.md

## Code Style

- Always preserve existing indentation style in each file, and validate it with
  `make clang-format`.
- Do not add inline comments explaining the change they belong to.

## Git Commit Rules

- Each logical change must be in its own separate commit.
- Fixes for existing commits in the current branch must use fixup commits:
  ```bash
  git commit --fixup=<original-commit-hash>
  ```

## Commit Authorship

- Keep the original author (do not change git config)
- Add agent signature at the end of commit messages.

## Adding New Files

- New source or test files must be added to `Makefile.am`
- After adding files, verify the build with `make distcheck`

## Adding New Tests

- Python tests go in `tests/test_*.py`, register in `all_tests` dict, and add to `PYTHON_TESTS` in root `Makefile.am`
- C unit tests go in `tests/tests_libcrun_*.c`, add to `UNIT_TESTS` in root `Makefile.am` with build rules
- Test functions should return `0` (pass), `-1` (fail), or `77` (skip)
