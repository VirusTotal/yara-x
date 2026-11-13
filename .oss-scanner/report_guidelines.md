# Report Guidelines

- **Tone and length**: Keep reports concise, factual, and technical (aim for under 600 words outside the reproducer). Avoid speculative impact claims.
- **Required sections**:
  1. **Summary & Trigger Vector**: 1–3 sentences stating the bug class, impact, and whether it is triggered by **untrusted scanned data**, **untrusted YARA source rules**, or both.
  2. **Root Cause**: Exact crate, file path, line numbers, and function name, explaining the broken invariant (e.g., unchecked offset arithmetic, `unsafe` lifetime/aliasing violation, slice indexing panic, unbounded allocation before bounds validation).
  3. **Minimal Reproducer**: Provide a self-contained Rust unit test (using `yara_x::compile` / `yara_x::Scanner`) or exact `yr` CLI invocation with minimal inline hex/base64 input bytes and rule text that reproduces the issue inside `/src`.
- **Timeout check for DoS findings**: For any hang, catastrophic backtracking, or CPU-exhaustion report during scanning, verify and state that the issue reproduces even when `Scanner::set_timeout(Duration::from_secs(2))` (or `yr scan --timeout=2`) is set.
