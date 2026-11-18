# Repository Agent Guidelines (`homerouter/shoes`)

Every AI assistant operating in this repository **MUST** follow these mandatory rules without exception. For full step-by-step release instructions, see [`.agents/skills/release/SKILL.md`](./.agents/skills/release/SKILL.md).

## Mandatory Version Bump & Release Rules

1. **Upstream-Anchored Versioning (`<UPSTREAM>.<REV>`)**:
   - Never independently bump major/minor versions (e.g. `0.4.x`, `0.5.x`).
   - Version numbers MUST anchor to upstream's release tag (`<UPSTREAM>`) with a dot-separated downstream revision suffix (`.<REV>`), e.g. `0.3.8.1` (git tag `v0.3.8.1`).
   - Subsequent releases based on the same upstream version increment the revision suffix (`0.3.8.2`, `0.3.8.3`). When upstream releases a new version (e.g. `0.3.9`), update the base version and reset the revision to `0.3.9.1`.
   - *Technical constraint & version decoupling*: Cargo strictly enforces SemVer 2.0.0; four-part numeric versions (`0.3.8.1`) trigger syntax errors in `Cargo.toml`. To comply with Cargo while avoiding awkward Alpine Linux APK naming (`APKBUILD` forbids hyphens in `pkgver`), `Cargo.toml` and `Cargo.lock` maintain the upstream base version (`0.3.8`), while `build.rs` injects `<UPSTREAM>.<REV>` via `SHOES_RELEASE_TAG`, matching git tags (`v0.3.8.1`), debian package (`0.3.8.1`), changelog (`v0.3.8.1`), and binary runtime output (`shoes --version`).
2. **Keep ONLY ONE `Bump version` commit on `dev`**:
   - Never stack or leave multiple `Bump version` commits in `dev` history (`git log --grep="^Bump version$" --oneline` MUST have at most **1** commit).
   - If a prior `Bump version` commit exists on `dev` when cutting a new release, replay non-bump commits cleanly onto its base commit (with `--rebase-merges` if needed) and combine prior changelog/debian entries with the new version into **one single** `Bump version` commit (reference: `8c147996ec95308b1ed37d0713b4638123904515`). Leave existing older release tags (e.g., `v0.4.4`) intact.
3. **Exact 4-file `Bump version` scope**:
   - Use commit message `Bump version` and modify ONLY `CHANGELOG.md`, `Cargo.toml`, `Cargo.lock`, and `debian/changelog`.
4. **Release from WSL only**:
   - Execute all version bumps, git history rewrites, annotated tag creation (`v<UPSTREAM>.<REV>`), pushes, and GitHub Release checks from **WSL (`lenovo`, `/home/ezhang/shoes`)** — never from `nrt` or other remote VPS nodes.
5. **Verify**:
   - Confirm `Bump version` commit count on `dev` equals `1`, `Cargo.toml`/`Cargo.lock` match `<UPSTREAM>`, `CHANGELOG.md`/`debian/changelog`/git tag match `<UPSTREAM>.<REV>`, and `.github/workflows/release.yml` publishes `amd64`, `arm64`, and `SHA256SUMS`.
