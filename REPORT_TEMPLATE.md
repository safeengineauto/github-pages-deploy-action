# Report template — OSS Security Scout

> This file is the **template**. Each cycle writes a copy to
> `reports/<YYYY-MM-DD>-<target-slug>.md` and fills in every section below.
> Sections marked *required* must be present even if the answer is "n/a".

---

# <Target slug> — <one-line summary of result>

## Provenance *(required)*

- **Target repo:** `<owner>/<repo>` (link)
- **Commit audited:** `<full SHA>` (`<one-line subject>`)
- **Default branch at audit time:** `<branch>` @ `<short SHA>`
- **License:** `<SPDX id>`
- **Run type:** `initial` | `crosscheck` | `followup`
- **Cycle date (UTC):** `<YYYY-MM-DD>`
- **Reviewer:** OSS Security Scout (cycle <N or date>)
- **Prior cycles for this target:** none | list of report paths

## Verdict *(required)*

One paragraph. State the headline finding, severity (P1/P2/P3/Info), and
the trust boundary it crosses (or "no boundary crossed → P3/Info").

## Threat model *(required)*

Briefly enumerate:

- What inputs the project trusts vs. distrusts.
- Who the realistic attacker is (PR author from a fork, comment author,
  workflow author, registry mirror, etc.).
- Which trust boundary, if any, this report's findings cross.

This section disciplines severity. A finding cannot be P1 unless this
section names a real attacker who reaches the sink without already having
the impact.

## Surface inventory *(required)*

List the security-relevant entry points, one per bullet. Cite code:

```<startLine>:<endLine>:<file path>
<short snippet>
```

Typical entries:

- Action inputs (`action.yml`)
- `process.env.*` reads
- `exec` / `execFile` / shell sinks
- File-write sinks (`fs.writeFile`, `fs.cp`, `tar.x`, etc.)
- Network sinks (`fetch`, `axios`, `got`)
- Auth handling (token usage, SSH key handling)

## Findings *(required)*

For each finding, use the following block. Repeat per finding. If there are
no findings, write "None — see `Notes` for hardening suggestions."

### Finding F-<n>: <short title>

- **Severity:** P1 | P2 | P3 | Info
- **Confidence:** High | Medium | Low
- **Affected:** `<file>:<lines>` (and any related files)
- **Trust boundary crossed:** yes (describe) | no (defense-in-depth)

**Description.** What the bug is, in plain language.

**Evidence.**

```<startLine>:<endLine>:<file>
<minimal code citation>
```

**Reachability.** Concrete walk from an attacker-controllable input to the
sink, naming each hop. If reachability requires conditions (e.g. a specific
workflow trigger), state them.

**Exploit sketch.** Smallest plausible PoC or input that triggers the bug.
Do NOT include working malicious payloads beyond what is needed to make the
finding reproducible.

**Suggested fix.** Smallest change that closes the gap, with a code citation
to the exact lines that would change.

**Notes.** Anything else (related issues, prior CVEs, false-positive
adjacencies).

## No-finding zones *(required)*

A short list of areas the scout *did* read and explicitly cleared (or
deferred). This is what makes a "no findings" report auditable. Examples:

- "Reviewed all `exec`/`execFile` callers in `src/`; all arguments are
  array-form and inputs are validated."
- "Did not review `lib/` (compiled output)."

## Recommendations *(optional)*

Hardening items that are not findings. P3/Info-level only.

## References *(required)*

- Target repo URL pinned at the audited SHA.
- Any CVEs, advisories, or prior reviews you relied on.
- Any related reports in this control repo.

## Reproducibility checklist *(required)*

- [ ] All cited line numbers refer to the audited SHA (`<SHA>`).
- [ ] No code from the target was executed during the cycle.
- [ ] All written files for this cycle are inside the control repo.
- [ ] Memory updated with this target.
