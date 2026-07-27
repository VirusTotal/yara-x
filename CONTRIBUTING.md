# Contributing to YARA-X

Thank you for your interest in contributing to YARA-X! We welcome contributions
from the community, whether it's reporting bugs, improving documentation, or 
submitting pull requests.

## Contributor License Agreement (CLA)

YARA-X is a project maintained by VirusTotal (a subsidiary of Google). 
Contributions to this project must be accompanied by a Contributor License
Agreement (CLA).

### Signing the CLA

Before we can accept and merge your pull requests, you will need to sign a 
Contributor License Agreement:

* **Individual CLA:** If you are contributing as an individual, please complete
  the online [Individual Contributor License Agreement](https://cla.developers.google.com/about).
* **Corporate CLA:** If you are contributing on behalf of your employer, your 
  organization must sign a [Corporate Contributor License Agreement](https://cla.developers.google.com/about).

When you open a pull request, an automated status check (`cla/google`) will 
verify whether you have signed the CLA. If you have not signed it yet, follow
the link provided by the status check to complete the agreement.

### `CONTRIBUTORS` and `AUTHORS` Files

* **`CONTRIBUTORS`**: Lists individuals who are authorized to contribute code
  to the repository. Names and email addresses are added after the individual 
  or their organization agrees to the CLA.
* **`AUTHORS`**: Lists copyright holders for the repository (such as Google Inc. 
  or corporate contributors).

---

## Code Style & Formatting

We adhere to standard Rust coding conventions and enforce code quality checks
in CI:

1. **Formatting (`rustfmt`):**
   * Code formatting is configured via [`rustfmt.toml`](rustfmt.toml) (e.g. `max_width = 79`).
   * Format your code before submitting a PR:
     ```bash
     cargo fmt --all
     ```
   * Verify formatting compliance locally:
     ```bash
     cargo fmt --all --check
     ```

2. **Linting (`clippy`):**
   * We use Clippy to ensure clean, idiomatic Rust code.
   * Ensure there are no Clippy warnings or errors before submitting your PR:
     ```bash
     cargo clippy --workspace --tests --no-deps -- --deny clippy::all
     ```

3. **Style References:**
   * Refer to the canonical [Rust Style Guide](https://doc.rust-lang.org/style-guide/) for style rules.

---

## Development & Contribution Workflow

Follow these steps to contribute code or fixes:

1. **Fork & Clone:**
   * Fork the [YARA-X repository](https://github.com/VirusTotal/yara-x) on GitHub and clone your fork locally.

2. **Create a Feature Branch:**
   * Create a branch for your changes:
     ```bash
     git checkout -b feature/my-changes
     ```

3. **Make Your Changes & Test:**
   * Implement your feature, bug fix, or documentation update.
   * Run the test suite:
     ```bash
     cargo test --workspace
     ```

4. **Verify Code Quality:**
   * Run formatting and linter checks:
     ```bash
     cargo fmt --all --check
     cargo clippy --workspace --tests --no-deps -- --deny clippy::all
     ```

5. **Submit a Pull Request:**
   * Push your branch to your GitHub fork and open a Pull Request against `main`.
   * Ensure you have signed the Google CLA so the `cla/google` status check passes.

---

## Reporting Issues

If you encounter bugs or have feature requests, please check existing issues
before opening a new one. Feel free to [open a new issue](https://github.com/VirusTotal/yara-x/issues/new) 
with detailed reproduction steps or feature context.
