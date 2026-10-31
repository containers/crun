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

## Man pages

- `crun.1` and `krun.1` are generated from `crun.1.md` and `krun.1.md` and
  kept in git. After changing a `.md` file, run `make generate-man` and
  commit the regenerated man page in the same commit.

## Error handling

- C code error handling convention is described in [design-docs/error_handling.md](design-docs/error_handling.md)

## Pull Requests

Before helping to prepare a pull request, make sure the bug is real (shown
by a reproducer, not just found by reading code) and the change is minimal
and fixes the root cause. The user must test the change, understand it, and
submit it and answer review questions themselves; if that is not the case,
say so and stop.
