---
name: shoes-release
description: Release and version-bump procedure for homerouter/shoes. Use whenever bumping package versions, updating CHANGELOG.md or debian/changelog for a release, tagging v*, or publishing release assets.
---

# Release & Version Bump Skill (`homerouter/shoes`)

## Mandatory Invariants

1. **Keep ONLY ONE `Bump version` commit on `dev`**:
   - `git log --grep="^Bump version$" --oneline` on `dev` MUST contain at most **1** commit.
   - **Never** stack multiple `Bump version` commits across releases.
2. **Release from WSL only**:
   - Execute all release commits, history rewrites, annotated tag creations (`v<X.Y.Z>`), and pushes from **WSL (`lenovo`, `/home/ezhang/work/shoes`)** with GPG signing and `gh` auth (`debiansid`).
   - **Never** create, bump, tag, or push `homerouter/shoes` releases from `nrt` or other remote VPS nodes.

## Procedure

1. Check existing bumps on `dev`:
   ```bash
   git log --grep="^Bump version$" --oneline
   ```
2. If an earlier `Bump version` commit already exists on `dev`:
   - Rebase/replay non-bump commits onto the commit before the old `Bump version` (preserving merges with `git rebase --rebase-merges` when present).
   - Keep older published release tags (e.g. `v0.4.0`) untouched unless explicitly instructed to re-tag an already published version.
   - Fold/merge prior `CHANGELOG.md` release sections and `debian/changelog` entries together with the new `<X.Y.Z>` changes into **one single** `Bump version` commit at the tip (`HEAD`).
3. Create the single commit with exact subject **`Bump version`**, touching ONLY these 4 files (reference: `8c147996ec95308b1ed37d0713b4638123904515`):
   - `Cargo.toml` (`[package].version = "<X.Y.Z>"`)
   - `Cargo.lock` (`[[package]]` `name = "shoes"` `version = "<X.Y.Z>"`)
   - `CHANGELOG.md` (`## v<X.Y.Z>` under `## Unreleased`, retaining previous release notes)
   - `debian/changelog` (prepend `shoes (<X.Y.Z>) unstable; urgency=medium` above earlier stanzas)
4. Tag and push from WSL:
   ```bash
   git tag -a "v<X.Y.Z>" -m "Release v<X.Y.Z>"
   git push origin dev "refs/tags/v<X.Y.Z>" # use --force-with-lease on dev / --force on tag only when rewriting/re-tagging
   ```
5. Verify before and after pushing:
   - `git log --grep="^Bump version$" --oneline | wc -l` equals `1`.
   - `Cargo.toml`, `Cargo.lock`, top `CHANGELOG.md` heading, top `debian/changelog` stanza, and tag `v<X.Y.Z>` all match `<X.Y.Z>` (consistent with `.github/workflows/release.yml`).
   - Wait for `.github/workflows/release.yml` to finish and confirm `shoes_<X.Y.Z>_amd64.deb`, `shoes_<X.Y.Z>_arm64.deb`, and `SHA256SUMS` are published on the GitHub Release.
