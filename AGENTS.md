# Repository Agent Guidelines (`homerouter/shoes`)

Every AI assistant operating in this repository **MUST** follow these mandatory rules without exception. For full step-by-step release instructions, see [`.agents/skills/release/SKILL.md`](./.agents/skills/release/SKILL.md).

## Mandatory Version Bump & Release Rules

1. **Keep ONLY ONE `Bump version` commit on `dev`**:
   - Never stack or leave multiple `Bump version` commits in `dev` history (`git log --grep="^Bump version$" --oneline` MUST have at most **1** commit).
   - If a prior `Bump version` commit exists on `dev` when cutting a new release, replay non-bump commits cleanly onto its base commit (with `--rebase-merges` if needed) and combine prior changelog/debian entries with the new version into **one single** `Bump version` commit (reference: `8c147996ec95308b1ed37d0713b4638123904515`). Leave existing older release tags (e.g., `v0.4.0`) intact.
2. **Exact 4-file `Bump version` scope**:
   - Use commit message `Bump version` and modify ONLY `CHANGELOG.md`, `Cargo.toml`, `Cargo.lock`, and `debian/changelog`.
3. **Release from WSL only**:
   - Execute all version bumps, git history rewrites, annotated tag creation (`v<X.Y.Z>`), pushes, and GitHub Release checks from **WSL (`lenovo`, `/home/ezhang/work/shoes`)** — never from `nrt` or other remote VPS nodes.
4. **Verify**:
   - Confirm `Bump version` commit count on `dev` equals `1`, all 4 version files match `<X.Y.Z>`, and `.github/workflows/release.yml` publishes `amd64`, `arm64`, and `SHA256SUMS`.
