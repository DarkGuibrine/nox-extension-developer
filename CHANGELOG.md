# Changelog

## 2.1.0

Security hardening, automated beginner workflows, and Issue #10 CLI fix:

- **Fix [Issue #10](https://github.com/ProjectNox-org/nox-extension-developer/issues/10) — Global CLI flags anywhere (`scripts/nox.py`):**
  - Propagated `--json`, `--beginner`, `--technical`, `--dry-run`, and non-conflicting `--lang` recursively across top-level parsers, subcommands, and nested subcommands (`doctor --json`, `--json doctor`, `lab image <file> --json`, `issues verify-historical --json`, `adb doctor --json`) while preserving `scaffold --lang` for extension source language.
- **Fail-closed Bubblewrap sandbox & Gradle execution chain verification (`scripts/nox_android.py`, `scripts/nox_enhancements.py`, `scripts/nox.py`):**
  - Added `verify_gradle_execution_chain` (checks `gradlew` regular-file confinement & suspicious shell commands, strict `urlsplit` host check on `distributionUrl`, mandatory valid `distributionSha256Sum` matched against `KNOWN_OFFICIAL_GRADLE_SHA256`, ZIP/manifest validation of `gradle-wrapper.jar` without native binaries, and rejection of repo `init.gradle*` or `-javaagent` flags in `gradle.properties`).
  - Added `probe_bwrap_sandbox` and `run_in_bwrap_sandbox` (`--unshare-all`, `--unshare-net` by default, `--die-with-parent`, `--new-session`, `--clearenv`, ephemeral staging copy excluding `.git`/symlinks/secrets, no `$HOME`/`~/.ssh`/`~/.agents` exposure).
  - Updated `build_debug_apk` and `nox.py bisect --test-cmd` to fail **closed** (`BLOCKED`, `executed_unprotected: false`) when Bubblewrap isolation is unavailable — zero host fallback.
  - Hardened `run_git_bisect_regression` with `-c core.hooksPath=/dev/null -c protocol.file.allow=never` and per-commit `audit_untrusted_pr_or_repo` gating.
- **Automated beginner-first orchestration & loop prevention (`scripts/nox_core.py`, `scripts/nox_scaffold.py`, `scripts/nox.py`, `SKILL.md`):**
  - Added `format_adaptive_response`, `detect_investigation_loop`, `build_optional_adb_guide`, `auto_create_extension`, `auto_fix_extension`, plus `nox.py auto`, `nox.py auto-create`, `nox.py auto-fix`, and `--technical`.
  - Streamlined `SKILL.md` and bilingual guides so beginners do not need technical jargon or physical Android devices unless optional runtime debugging is explicitly needed.

## 2.0.0

Major local engineering upgrade (`1,200` traced items: `1,000` original catalog requirements + `200` autonomous enhancements):

- **Modular local CLI (`scripts/nox.py`) & core evidence engine (`scripts/nox_core.py`):**
  - Added strict evidence statuses (`PASS`, `FAIL`, `INCONCLUSIVE`, `BLOCKED`, `NOT_RUN`), SHA-256 execution receipts, unsupported-claim gate, `nox.py report`, and `nox.py verify-report`.
- **Environment Doctor, Scaffolding & Structural API Compare (`scripts/nox_env.py`, `scripts/nox_scaffold.py`, `scripts/api_compare.py`):**
  - Added `doctor`, `inspect` (detecting Keiyoushi `KeiSource`, Yuzono `AniSource`, LNReader, KSP vs legacy, deterministic 64-bit MD5 `sourceId`), `search-existing`, dependency/reproducibility/compliance checks, `scaffold` + ephemeral HTTP functional scenarios (`scenarios`), and structural multiline API comparison with quality/Hermes checks.
- **Site DNA, Media & Image Lab (`scripts/nox_lab.py`):**
  - Added `site-inspect`, real image magic bytes/dimension inspection (rejecting deceptive HTTP 200 HTML/SVG), `unscramble_image_slices` (permutation bijection + DRM/EME block), `lab visual-diff` with PII redaction, fractional chapter continuity (`59.5`), Yuzono `getHosterList`/`getVideoList`/HLS/DASH/subtitles, LNReader readability, `search == popular` guard, HAR replay, disk-persisted budget-enforced canary monitor, and mutation self-testing.
- **Android Build, APK/DEX Inspection & ADB/Logcat (`scripts/nox_android.py`):**
  - Added security-gated `build` (`gradlew assembleDebug`), `apk-inspect` (`aapt2`/`apksigner`, SHA-256, Debug vs Release, conditional 16 KB `.so` check), `api-binary-compare` (`.dex`/`.class`/`.jar`), `deeplink-check`, `adb doctor`, `parse_uiautomator_hierarchy_and_plan_actions` + `adb ui-plan` (hardware runs stay honestly `BLOCKED`/`NOT_RUN` when `adb devices` is empty), package/PID-isolated `adb filter-logcat` with secret redaction, and `bisect`.
- **Multi-Ecosystem Nox Issue Intelligence (`scripts/nox_issues.py`):**
  - Added live GitHub API + pinned diff inspection across Keiyoushi (`keiyoushi/extensions-source`), Yuzono (`yuzono/anime-extensions`), and LNReader (`LNReader/lnreader-plugins`), strictly distinguishing `VERIFIED_FIX` from `MERGED_UNVERIFIED`, `REVERTED_FIX`, `OPEN_OR_UNMERGED`, `CLOSED_UNMERGED`, `SUPERSEDED`, and synthetic `merge_commit_sha` traps, plus cross-version copy guard, `autofix-diagnose`, and real-analyzer `review-council`.
- **Security & Supply-Chain Hardening (`scripts/nox_core.py`, `scripts/nox_android.py`, `scripts/nox_enhancements.py`):**
  - Added SSRF private/IPv4-mapped IPv6/numeric-IP/meta-refresh blocking, Gradle RCE/wrapper/workflow script-injection scanner, TLS/`DexClassLoader`/WebView/Zip-Bomb/Zip-Slip checks, Trojan Source (`scan_bidi_controls`), and secret redaction.
- **175 On-Demand Modular Enhancements (`scripts/nox_enhancements.py`) & 1,200-Item Matrix (`scripts/nox_matrix.py`):**
  - Registered `1026`–`1200` on-demand guards (`enhance --list`, `enhance --audit-source`) plus `1001`–`1025` core capabilities, frozen catalog `references/catalog-1000.json`, validated matrix `references/matrix-1000.json` + bilingual tables (`docs/pt-BR/matriz-1000.md`, `docs/en/matrix-1000.md`), dynamic `benchmark` comparing real `v1.0.3` baseline against current tooling, updated CI, and unit/integration test suites (`tests/`).

## 1.0.3

- Clarify Node.js version requirements and dependency setup for each ecosystem in both READMEs.
- Add concrete JDK, Android SDK, and project-local build guidance while preserving existing installations.

## 1.0.2

- Reorganize the Portuguese and English READMEs around a beginner-friendly setup and usage journey.
- Clarify ecosystem dependencies, agent compatibility, community resources, and licensing.

## 1.0.1

- Expand bilingual dependency and Android SDK guidance, add practical examples, and clarify Windows/WSL limitations.
- Document verified OpenCode discovery after installation from the public repository.

## 1.0.0

- Added an Agent Skills workflow for Keiyoushi, Yuzono, and LNReader, with on-demand official references pinned to upstream commits.
- Added integrity-checked snapshots, offline fallback, corruption quarantine, and serialized updates.
- Added scoped API comparison with conservative heuristics and documented uncertainty.
- Added local symlink installation and deterministic candidate packaging.
- Added regression tests and documented security, compatibility, licensing, and validation limits.
- Treat added API declarations as indeterminate; adding an interface method can break implementers.
- Read package inputs without following symlinks and publish complete ZIPs without replacing an existing file.
- Clarified natural-language examples, synthetic-test limits, and the owner’s licensing decision.
- Treat unknown or nonnumeric version identifiers as indeterminate in scoped API comparisons.
- Require a known-positive search check and clarify site inspection, dependency reuse, and resuming interrupted work.
- Include both language guides, prompts, and visual assets in the distribution ZIP.
- Install under the canonical skill name even when the source directory was renamed.

Released under AGPL-3.0-only. Third-party projects retain their own licenses; see `ATRIBUICOES.md`.
