# Security Policy

## 1. Introduction

This document outlines the security policy for the `postchain-client-rust` source code hosted in this GitHub repository. Our primary goal is to ensure the confidentiality, integrity, and availability of this client library and to safeguard applications that integrate it. All contributors are expected to adhere to this policy.

## 2. Scope

This policy applies to all source code, configurations, dependencies, tests, and documentation within the `postchain-client-rust` GitHub repository (https://github.com/cuonglb/postchain-client-rust) and any associated forks or branches.

## 3. Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in `postchain-client-rust`, please report it to us as soon as possible.

* **How to Report:**
    * **Preferred Method:** Use GitHub's private vulnerability reporting feature for this repository. Navigate to the "Security" tab and select "Report a vulnerability." This allows for secure, private communication during the disclosure process.
    * **Alternative Method (if private reporting is not available or urgent):** Please email us directly at **[YOUR_SECURITY_EMAIL_ADDRESS_HERE - *e.g., a personal email for a small project, or a dedicated security alias for a larger one*]** with a detailed description of the vulnerability.
* **Information to Include:**
    * A clear and concise description of the vulnerability.
    * Steps to reproduce the vulnerability, including any necessary setup or code snippets.
    * The specific version(s) of `postchain-client-rust` affected.
    * Any potential impact or exploit scenarios you foresee.
    * Suggested mitigation or fix (if known).
* **Our Commitment:** We commit to acknowledging receipt of your report within **3 business days** and will provide regular updates on the remediation progress. We kindly request that you do not disclose the vulnerability publicly until we have had a reasonable opportunity to investigate and address it. We aim to resolve critical vulnerabilities within **30 days** where possible.

## 4. Development Security Best Practices

All contributors are expected to follow these best practices during development of `postchain-client-rust`:

### 4.1. Code Reviews

* All code changes must undergo a thorough code review by at least **one (1)** other team member before being merged into the `master` (or designated stable) branch.
* Reviewers should pay close attention to potential security issues, particularly:
    * **Input Validation & Sanitization:** Ensure all data received from external sources (e.g., node responses, user input for transaction parameters) is rigorously validated and sanitized to prevent injection attacks or unexpected behavior. This is especially critical when constructing blockchain operations.
    * **Cryptographic Operations:** Verify correct and secure usage of cryptographic primitives (e.g., signing transactions, hashing). Avoid custom cryptographic implementations; prefer well-vetted Rust crates.
    * **Error Handling:** Implement robust error handling for network communication, deserialization, and cryptographic failures to prevent denial-of-service or information leakage.
    * **State Management:** Ensure that the client's internal state (e.g., connected nodes, transaction builders) is managed securely and consistently.
    * **Prevention of Common Vulnerabilities:** Be aware of and actively prevent common vulnerabilities like integer overflows, panics in critical paths, and improper resource handling.

### 4.2. Secure Coding Principles (Rust Specific)

* **Leverage Rust's Safety Features:**
    * Minimize `unsafe` code blocks. When `unsafe` code is necessary, ensure it is thoroughly documented, reviewed, and justified with a clear safety invariant.
    * Utilize Rust's ownership and borrowing system to prevent memory safety issues (e.g., use-after-free, double-free).
* **Input Handling:**
    * Use Rust's strong typing and `Result`/`Option` for explicit error handling, rather than `unwrap()` or `expect()` in production-critical paths, especially when dealing with untrusted input or network responses.
    * Validate data types and formats carefully.
* **Secure Randomness:** When generating nonces, unique transaction IDs, or any other value requiring randomness for security purposes, use cryptographically secure random number generators (e.g., `rand_core::OsRng` or similar from trusted crates).
* **Secrets Management:**
    * **NEVER** hardcode sensitive information (e.g., private keys, seed phrases, access tokens, API keys for external services) into the source code.
    * The client library itself should not manage user-specific secrets. Users of the library are responsible for securely managing their private keys and other sensitive data. The library should only handle these as transient, securely-passed parameters.
* **Resource Management:** Ensure proper handling of network connections and file descriptors to prevent resource exhaustion attacks.

### 4.3. Dependency Management

* **Regular Updates:** Regularly update Rust dependencies (`Cargo.toml` and `Cargo.lock`) to their latest secure versions.
* **Software Composition Analysis (SCA):**
    * Integrate a tool like `cargo-audit` (which uses the RustSec Advisory Database) into the CI/CD pipeline to automatically scan for known vulnerabilities in third-party crates.
    * Address any reported vulnerabilities promptly.
* **Dependency Review:** Exercise caution when adding new dependencies. Prefer well-maintained, widely used, and security-audited crates.

### 4.4. Branch Protection Rules

* The `master` branch (or any other main development/release branch) must be protected.
* Require at least one approved pull request review before merging.
* Require status checks (e.g., CI/CD build, security scans, tests) to pass before merging.
* Restrict direct pushes to the `master` branch.

### 4.5. Continuous Integration / Continuous Delivery (CI/CD) Security

* Integrate security checks into the CI/CD pipeline. This includes:
    * **`cargo check`** and **`cargo clippy`**: For static analysis and adherence to Rust best practices.
    * **`cargo test`**: Comprehensive unit and integration tests.
    * **`cargo audit`**: Automated vulnerability scanning of dependencies.
    * Potentially, other static analysis (SAST) tools if available for Rust.
* Ensure CI/CD build environments are secure, ephemeral, and isolated.
* Manage CI/CD secrets (if any) securely using GitHub Actions Secrets or similar mechanisms.

## 5. Access Control

* Access to the GitHub repository and its branches will be granted based on the principle of least privilege.
* Collaborator access will be regularly reviewed and revoked when no longer necessary.
* All maintainers and direct contributors are strongly encouraged to enable two-factor authentication (2FA) for their GitHub accounts.

## 6. Incident Response

* In the event of a suspected security incident, immediately notify **[YOUR_SECURITY_EMAIL_ADDRESS_HERE]** or report via the private vulnerability reporting channel.
* A designated team member will lead the incident response, which includes:
    * Containment of the issue.
    * Investigation and root cause analysis.
    * Remediation and patching.
    * Post-incident review.
    * Responsible disclosure to affected parties (users of the library, if necessary).

## 7. Compliance

* As a general-purpose client library, specific compliance regulations like GDPR or HIPAA may not directly apply to the library itself, but they will apply to the applications that *use* this library and handle sensitive data. This policy aims to provide a secure foundation for such applications.

## 8. Policy Review and Updates

This security policy will be reviewed periodically (at least annually) and updated as necessary to reflect changes in best practices, the Rust ecosystem, and the `postchain-client-rust` project's requirements.
