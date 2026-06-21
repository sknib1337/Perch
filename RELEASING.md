# Releasing Perch to PyPI

Perch publishes to PyPI as **`perch-host`** (the import/command name is `perch`;
the distribution name differs because `perch` was already taken). Publishing is
automated by `.github/workflows/release.yml` using **PyPI Trusted Publishing
(OIDC)** — no API tokens are stored in the repo.

## One-time setup

Do these two things once.

### 1. Create the `pypi` GitHub environment

In the repo: **Settings → Environments → New environment**, name it exactly
`pypi`. (Optional but recommended: add yourself as a required reviewer so a human
approves every publish.)

### 2. Register the trusted publisher on PyPI

On <https://pypi.org>, log in, then:

- If `perch-host` **doesn't exist yet** (first release): go to your account →
  **Publishing** → **Add a pending publisher**.
- If it already exists: go to the project → **Settings → Publishing**.

Fill in exactly:

| Field | Value |
|---|---|
| PyPI project name | `perch-host` |
| Owner | `sknib1337` |
| Repository name | `Perch` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

That authorizes this repo's `release.yml` (running in the `pypi` environment) to
publish, with no secrets.

## Cutting a release

1. **Bump the version** in `perch/__init__.py`:
   ```python
   __version__ = "0.4.0"
   ```
   That's the only place — `pyproject.toml` reads it dynamically.
2. **Commit and push** to `main`.
3. On GitHub: **Releases → Draft a new release**. Create a tag that matches the
   version with a `v` prefix (e.g. `v0.4.0`), write release notes, and click
   **Publish release**.

Publishing the release triggers the workflow, which:

- runs the test suite,
- verifies the tag matches `perch.__version__` (fails the release if they differ),
- builds the sdist + wheel and runs `twine check`,
- publishes to PyPI via OIDC.

## Verify

After the run goes green:

- The package shows at <https://pypi.org/project/perch-host/>.
- A fresh install works:
  ```bash
  pip install perch-host
  perch --help
  ```

## Notes

- **TestPyPI dry run (optional):** register a trusted publisher on
  <https://test.pypi.org> the same way, then temporarily add
  `with: { repository-url: https://test.pypi.org/legacy/ }` to the publish step to
  rehearse before the real thing.
- **Token alternative:** if you ever can't use OIDC, create a PyPI API token,
  store it as the repo secret `PYPI_API_TOKEN`, and add
  `with: { password: ${{ secrets.PYPI_API_TOKEN }} }` to the publish step.
  Trusted Publishing is preferred — keep tokens as a fallback only.
- The separate `ci.yml` workflow runs the tests on every push and pull request;
  `release.yml` only runs when you publish a Release.
