## Target Policy

Run selection rules for OSS Security Scout cycles in this control repository:

1. Run exactly one target per cycle.
2. Respect memory and avoid targets already listed as completed/reviewed unless explicitly requested.
3. Prefer high-risk surfaces first:
   - command execution wrappers
   - git or shell argument construction
   - path handling and filesystem mutation
   - auth/token/secret handling
4. For an initial run, choose one medium-to-high risk file/function and document rationale.
5. Keep all cycle artifacts (report + memory) inside this repository.
