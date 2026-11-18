---
name: shoes-release
description: Release and version-bump procedure for homerouter/shoes. Use whenever bumping package versions, updating CHANGELOG.md or debian/changelog for a release, tagging v*, or publishing release assets.
---

# Release & Version Bump Skill (`homerouter/shoes`)

## Mandatory Invariants

1. **Upstream-Anchored Versioning (`<UPSTREAM>.<REV>`)**:
   - Never independently bump major/minor versions (e.g. `0.4.x`, `0.5.x`).
   - Version numbers MUST anchor to upstream's release tag (`<UPSTREAM>`) with a dot-separated downstream revision suffix (`.<REV>`), e.g. `0.3.8.1`, tag `v0.3.8.1`.
   - Subsequent releases based on the same upstream version bump the suffix (`0.3.8.2`, `0.3.8.3`). When upstream cuts a new release (e.g. `0.3.9`), the base version updates and the revision resets to `0.3.9.1`.
   - *Technical requirement & version decoupling*: Cargo enforces SemVer 2.0.0; four-part dot-separated versions like `0.3.8.1` cause Cargo syntax errors (`unexpected character '.' after patch version number`). Meanwhile, Alpine Linux `APKBUILD` forbids hyphens in `pkgver`, so `0.3.8-1` produces `shoes-0.3.8-1-r1.apk`. To satisfy both, `Cargo.toml` and `Cargo.lock` maintain upstream base version (`0.3.8`), while `build.rs` injects `<UPSTREAM>.<REV>` via `SHOES_RELEASE_TAG`, aligning git tags (`v0.3.8.1`), Debian package (`0.3.8.1`), CHANGELOG (`v0.3.8.1`), and binary runtime output (`shoes --version`).
2. **Keep ONLY ONE `Bump version` commit on `dev`**:
   - `git log --grep="^Bump version$" --oneline` on `dev` MUST contain at most **1** commit.
   - **Never** stack multiple `Bump version` commits across releases.
3. **Release from WSL only**:
   - Execute all release commits, history rewrites, annotated tag creations (`v<UPSTREAM>.<REV>`), and pushes from **WSL (`lenovo`, `/home/ezhang/shoes`)** with GPG signing and `gh` auth (`debiansid`).
   - **Never** create, bump, tag, or push `homerouter/shoes` releases from `nrt` or other remote VPS nodes.

## Procedure

1. Check existing bumps on `dev`:
   ```bash
   git log --grep="^Bump version$" --oneline
   ```
2. If an earlier `Bump version` commit already exists on `dev`:
   - Rebase/replay non-bump commits onto the commit before the old `Bump version` (preserving merges with `git rebase --rebase-merges` when present).
   - Keep older published release tags (e.g. `v0.4.4`) untouched unless explicitly instructed to re-tag an already published version.
   - Fold/merge prior `CHANGELOG.md` release sections and `debian/changelog` entries together with the new `<UPSTREAM>.<REV>` changes into **one single** `Bump version` commit at the tip (`HEAD`).
3. Create the single commit with exact subject **`Bump version`**, touching ONLY these 4 files:
   - `Cargo.toml` (`[package].version = "<UPSTREAM>"`, e.g. `"0.3.8"`)
   - `Cargo.lock` (`[[package]]` `name = "shoes"` `version = "<UPSTREAM>"`)
   - `CHANGELOG.md` (`## v<UPSTREAM>.<REV>` under `## Unreleased`, retaining previous release notes)
   - `debian/changelog` (prepend `shoes (<UPSTREAM>.<REV>) unstable; urgency=medium` above earlier stanzas)
4. Tag and push from WSL:
   ```bash
   git tag -a "v<UPSTREAM>.<REV>" -m "Release v<UPSTREAM>.<REV>"
   git push origin dev "refs/tags/v<UPSTREAM>.<REV>" # use --force-with-lease on dev / --force on tag only when rewriting/re-tagging
   ```
5. Verify before and after pushing:
   - `git log --grep="^Bump version$" --oneline | wc -l` equals `1`.
   - `Cargo.toml` and `Cargo.lock` match `<UPSTREAM>`. Top `CHANGELOG.md` heading, top `debian/changelog` stanza, and tag `v<UPSTREAM>.<REV>` all match `<UPSTREAM>.<REV>` (consistent with `.github/workflows/release.yml`).
   - Wait for `.github/workflows/release.yml` to finish and confirm `shoes_<UPSTREAM>.<REV>_amd64.deb`, `shoes_<UPSTREAM>.<REV>_arm64.deb`, and `SHA256SUMS` are published on the GitHub Release.
