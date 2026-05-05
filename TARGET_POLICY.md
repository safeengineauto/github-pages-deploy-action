# Target Policy — OSS Security Scout

## Scope

Each audit evaluates the following areas of an open-source project:

### 1. Credential & Secret Handling
- Are tokens, SSH keys, or API keys ever logged, echoed, or written to
  world-readable locations?
- Is sensitive information masked/suppressed in error messages?
- Are secrets passed through environment variables or files with appropriate
  permissions?

### 2. Input Validation & Injection
- Are user-controlled inputs (action inputs, environment variables) validated
  before use?
- Could any input be used to inject shell commands, git arguments, or path
  traversals?
- Are string interpolations inside shell commands properly quoted/escaped?

### 3. Dependency & Supply-Chain Risk
- Are dependency versions pinned (lock files present and committed)?
- Are there known vulnerabilities in direct dependencies?
- Are CI/CD action references pinned to commit SHAs or version tags?

### 4. CI/CD & Workflow Security
- Do workflows follow least-privilege for `permissions`?
- Are `persist-credentials: false` and other hardening options used where
  appropriate?
- Could workflow triggers (e.g., `pull_request_target`, `workflow_dispatch`)
  be abused?

### 5. Cryptographic & Transport Security
- Are SSH known-host fingerprints validated?
- Are deprecated or weak key types in use?
- Is HTTPS enforced for remote operations?

### 6. Code Quality & Error Handling
- Are errors caught and reported without leaking sensitive data?
- Is there a clear security policy (SECURITY.md) and a responsible
  disclosure process?

## Severity Ratings

| Rating | Meaning |
|--------|---------|
| **Critical** | Immediate exploitation risk; credential leak, RCE, etc. |
| **High** | Likely exploitable with moderate effort. |
| **Medium** | Defense-in-depth gap; exploitation requires chaining. |
| **Low** | Best-practice deviation with minimal direct risk. |
| **Info** | Observation or recommendation, no immediate risk. |

## Out of Scope

* Performance benchmarks
* Feature completeness
* Licensing compliance (beyond noting if a license file exists)
