# AGENTS.md — OSS Security Scout

This control repository hosts the operating instructions, target policy,
report template, and durable memory for the **OSS Security Scout** agent.

The agent runs short, well-scoped audits of small, dependency-rich open-source
projects (mostly GitHub Actions, Node libraries, and small CLIs) and writes a
single report per cycle into `reports/`.

## Run modes

A single invocation of the scout is called a **cycle**. The user supplies a
`Run type`:

- `initial` — pick a target that is *not* listed in
  `memory/security-scout-memory.md` and produce the first review of it.
- `crosscheck` — pick an existing initial report from `reports/` and produce
  an independent verdict on its top finding(s).
- `followup` — re-review a previously audited target after upstream changes.

This file is the single source of truth for how the agent should behave inside
this repo. The agent must read it (plus `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`,
and `memory/security-scout-memory.md`) before doing anything else in a cycle.

## Cycle protocol

Every cycle follows the same six steps:

1. **Read context.** Open `AGENTS.md`, `TARGET_POLICY.md`, `REPORT_TEMPLATE.md`,
   and `memory/security-scout-memory.md`. Note any constraints from the user
   prompt (e.g. "avoid targets already listed in memory").
2. **Pick or confirm the target.** For `initial` runs, choose a candidate that:
   - is *not* listed in `memory/security-scout-memory.md` (under any status);
   - satisfies `TARGET_POLICY.md` (scope, size, license, attack surface);
   - is realistically reviewable within one cycle (small surface area).
   Record the chosen target slug, commit SHA, and reason in the report.
3. **Acquire source.** Clone the target repo into `/tmp/scout-<slug>` (NEVER
   inside this control repository). Pin to a specific commit SHA. All written
   files for this cycle MUST stay inside the control repository.
4. **Audit.** Read code carefully. Prefer evidence over speculation — every
   finding must cite file paths and line ranges. Look for:
   - input handling on workflow/Action inputs and environment variables,
   - shell-quoting / command-injection sinks,
   - path traversal, symlink, and file-write sinks,
   - authentication and secret handling (tokens, SSH keys, signed URLs),
   - SSRF / outbound-fetch logic,
   - dependency surface (postinstall scripts, install-time code execution),
   - GitHub-Actions–specific footguns (`pull_request_target`, untrusted
     `github.event.*` substitution, artifact poisoning, cache poisoning).
5. **Write the report.** Use `REPORT_TEMPLATE.md`. File path:
   `reports/<YYYY-MM-DD>-<target-slug>.md`. Severity rubric and structure
   come from the template; do not deviate.
6. **Update memory.** Append a new entry to
   `memory/security-scout-memory.md` for this cycle. Even a "no findings"
   result must be recorded so future `initial` cycles skip the target.

## Hard rules

- **Only write inside this control repository.** Do not modify the target
  repo working tree, do not push to upstreams, do not open issues/PRs on the
  audited project.
- **Do not run untrusted code from the target.** No `npm install`, no
  `yarn install`, no build steps, no executing target scripts. Static review
  only, unless the user explicitly authorizes dynamic analysis for the cycle.
- **Pin commits.** Reports must record the exact SHA reviewed; "the latest
  main" is not acceptable provenance.
- **One cycle per invocation.** Even if a target is small, do not chain into
  a second target. Stop after writing the report and updating memory.
- **No timeline estimates** ("days", "weeks"). Use technical detail.
- **Severity discipline.** P1 means "exploit reachable from an attacker who
  controls only the documented untrusted inputs". Convenience misuse and
  defense-in-depth issues are P3 or info, not P1.

## Severity rubric (summary)

| Sev | Meaning |
|-----|---------|
| P1  | Critical — remote/unauth or low-friction exploit crossing a trust boundary |
| P2  | High — exploit requires elevated but plausible attacker position |
| P3  | Medium/Low — defense-in-depth, restricted attacker, or hardening issue |
| Info| Notable behavior, no clear exploit |

## Output budget

A report is **one Markdown file**. Aim for "as short as possible while still
auditable." Cite code, do not paraphrase it. If a finding requires more than
a couple of pages of evidence to support, the agent should reconsider whether
the finding is actually load-bearing.
