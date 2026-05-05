# TARGET_POLICY.md — what the OSS Security Scout will and won't audit

This policy defines the scope of acceptable audit targets. The scout must
satisfy *every* "in scope" rule and avoid *every* "out of scope" rule before
selecting a target.

## In scope

- **Project type.** Public open-source projects on GitHub, primarily:
  - GitHub Actions (composite or JS/TS),
  - small Node.js / TypeScript libraries (under ~5k SLOC of first-party code),
  - small CLI tools written in Node, Go, Python, or Rust.
- **License.** OSI-approved permissive license (MIT, Apache-2.0, BSD, ISC) or
  similarly permissive. Copyleft (GPL-family) is acceptable for read-only
  static review.
- **Attack surface.** The project must process at least one of:
  - workflow inputs / `github.event.*` data,
  - tokens, SSH keys, or other credentials,
  - filesystem paths supplied at runtime,
  - network URLs supplied at runtime,
  - subprocess invocations driven by inputs.
- **Reviewability.** A single reviewer can plausibly read the security-relevant
  code in one cycle. Heuristic: first-party source ≤ ~5,000 lines, or the
  attack-surface subset ≤ ~1,500 lines.
- **Activity.** Project has a tagged release in the last 24 months, OR is a
  pinned dependency of a project the user already cares about.

## Out of scope

- Targets already listed in `memory/security-scout-memory.md` for `initial`
  cycles (regardless of status). They may still be revisited via `followup`
  or `crosscheck`.
- Projects with **no clear maintainer or trust line** (abandonware, single
  unverified author with no contact path) — still reviewable, but mark
  Info-only and disclose the maintainer-trust caveat in the report.
- Massive monorepos (e.g. full distributions, frameworks with 10k+ SLOC of
  attack-surface code). Pick a *subdirectory* as a separate target instead.
- Projects whose source license forbids static review or redistribution of
  short code citations.
- Anything that requires **dynamic execution** of untrusted code on the
  scout host. Static review only, unless the user explicitly authorizes
  sandboxed dynamic analysis for the cycle.
- Projects where the user has signaled a conflict of interest (e.g. they
  maintain it personally) unless they explicitly request the audit.

## Preferred shape of an `initial` target

In practice, the best targets for an initial cycle look like this:

- A single GitHub Action repo with one `action.yml` and a small `src/` tree.
- The action handles at least one credential-bearing input (token, SSH key,
  signed URL).
- The action shells out, writes files, or makes network requests using
  workflow-controlled inputs.
- The project is widely depended upon (high install/usage count) so a real
  finding has meaningful blast radius.

## Tiebreakers when several targets qualify

Prefer, in order:

1. Targets where the *control repo's own dependency graph* would be exposed
   to a finding (e.g. dependencies of `github-pages-deploy-action`).
2. Targets that have *not* received recent third-party security audits.
3. Targets with a small `src/` and a relatively complex `action.yml`
   (often a sign of input-validation surface).
4. Targets written in TypeScript / typed languages — easier to audit
   statically inside a single cycle.

## Things to *always* check before committing to a target

- License file present and permissive.
- Repo is not archived. (Archived = downgrade to `followup` only.)
- No outstanding embargoed advisory the agent is already aware of (avoid
  duplicating active disclosure work).
- Target slug `owner/repo` is recorded verbatim in the report and memory.
