# OSS Security Scout Report

## Cycle Metadata
- Cycle ID: initial-2026-05-05-1606z
- Run Type: initial
- Date (UTC): 2026-05-05T16:06:00Z
- Analyst: Codex 5.3
- Repository: JamesIves/github-pages-deploy-action

## Inputs Reviewed
- AGENTS.md: `/workspace/AGENTS.md` (created in this control repo because it was missing)
- TARGET_POLICY.md: `/workspace/TARGET_POLICY.md` (created in this control repo because it was missing)
- memory/security-scout-memory.md: `/workspace/memory/security-scout-memory.md` (created in this control repo because it was missing)

## Target Selection
- Candidate pool: `src/ssh.ts`, `src/git.ts`, `src/worktree.ts`, `src/util.ts`
- Excluded from memory: none (memory file started empty)
- Selected target: `src/git.ts`
- Rationale: This file handles deployment orchestration, remote git operations, worktree management, and shell command construction around potentially sensitive repository paths and user-provided settings.

## Method
1. Read `src/git.ts` and transitive helper usage (`src/execute.ts`, `src/worktree.ts`, `src/util.ts`, `src/constants.ts`).
2. Trace values that can be influenced by workflow inputs (`folder`, `target-folder`, `clean-exclude`, `branch`, `repository-name`, `token`).
3. Identify interpolation into shell command strings passed to `@actions/exec`.
4. Evaluate whether attacker-controlled content can trigger command injection or dangerous side effects.

## Findings
### Finding ID: SSC-2026-0001
- Title: Command injection risk via unescaped `clean-exclude` patterns in rsync command assembly
- Severity: High
- CWE: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
- Confidence: Medium
- Affected files: `src/git.ts` (lines ~156-161 and ~172-202)
- Summary: User-provided `clean-exclude` entries are directly concatenated into an rsync shell command without escaping, allowing shell metacharacters to alter command execution.
- Evidence:
  - `src/constants.ts` reads `clean-exclude` from user input and stores raw lines:
    - `cleanExclude: (getInput('clean-exclude') || '').split('\n').filter(l => l !== '')`
  - `src/git.ts` builds flags with direct concatenation:
    - `excludes += \`--exclude ${item} \``
  - The resulting `excludes` is embedded into a single command string for `execute(...)`:
    - `rsync ... ${action.clean ? \`--delete ${excludes} ...\` : ''} ...`
  - `execute(...)` then invokes `@actions/exec` with the entire string command (`exec(cmd, [], ...)`), which can execute shell metacharacter expansions depending on runtime shell handling.
- Impact:
  - A malicious workflow input could inject additional arguments or commands, potentially leading to arbitrary command execution in the GitHub Actions runner context.
  - In public repositories or reusable workflows where inputs may be influenced indirectly, this can escalate from integrity risk to credential/token exposure risk.
- Reproduction sketch:
  1. Configure workflow input `clean-exclude` with a crafted line containing shell metacharacters (e.g., separators or command substitution).
  2. Enable `clean: true`.
  3. Observe execution of altered rsync invocation in action logs.
- Recommendation:
  - Avoid building shell commands via string concatenation for user-controlled values.
  - Pass commands/arguments as structured arrays (binary + args) and ensure strict escaping.
  - Validate `clean-exclude` against an allowlist (safe path pattern characters only), rejecting metacharacters.

## No-Finding Notes
- Areas reviewed without confirmed vulnerability:
  - Retry/push logic and rejection handling in deploy flow.
  - Cleanup worktree removal path (appears deterministic, not attacker-selected in normal mode).

## Memory Update Payload
- Add target(s): `src/git.ts`
- Add finding ID(s): `SSC-2026-0001`
- Next-cycle avoid list: `src/git.ts`
