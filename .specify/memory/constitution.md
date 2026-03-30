<!--
  Sync Impact Report
  ===================
  Version change: 0.0.0 (template) → 1.0.0
  Modified principles: N/A (initial population from template)
  Added sections:
    - Core Principles (7 principles populated)
    - Security Requirements & Constraints (new)
    - Development Workflow & Quality Gates (new)
    - Governance (populated)
  Removed sections: None
  Templates requiring updates:
    - .specify/templates/plan-template.md — ✅ no changes needed
      (Constitution Check section already references constitution)
    - .specify/templates/spec-template.md — ✅ no changes needed
      (user stories / requirements structure is compatible)
    - .specify/templates/tasks-template.md — ✅ no changes needed
      (task phases accommodate security-specific tasks)
    - .specify/templates/checklist-template.md — ✅ no changes needed
    - .specify/templates/agent-file-template.md — ✅ no changes needed
  Follow-up TODOs: None
-->

# Secure Keyboard Constitution

## Core Principles

### I. Security-First (NON-NEGOTIABLE)

Every design decision, code change, and architectural choice MUST
prioritize security above convenience, speed-to-ship, or feature
breadth. This is a cybersecurity product—security failures are
existential failures.

- All data at rest and in transit MUST be encrypted with
  authenticated encryption (AEAD). No exceptions.
- The server MUST never have access to plaintext user messages
  or private key material. Zero-knowledge by design.
- All cryptographic operations (key generation, encryption,
  decryption, signing, key exchange) MUST execute on-device.
  The server is an untrusted relay.
- Secret material (private keys, master secrets, session keys)
  MUST be stored in Android Keystore or EncryptedSharedPreferences.
  Plain SharedPreferences or in-memory-only storage is prohibited
  for persistent secrets.
- Every new feature MUST include a threat model assessment
  before implementation begins, identifying attack surfaces,
  trust boundaries, and mitigations.

**Rationale**: The product's core value proposition is
confidential, surveillance-resistant communication. A single
security regression destroys user trust irreversibly.

### II. Correctness Over Convenience (NON-NEGOTIABLE)

Every implementation MUST produce correct, verifiable results.
No mock, stub, or placeholder code is permitted in any
deliverable that reaches a release branch.

- Mock implementations (fake encryption, hardcoded keys,
  random "decoy" substitution without real steganography)
  are strictly prohibited in production code paths.
- Each cryptographic primitive MUST be validated against
  known test vectors (RFC 8439 for ChaCha20-Poly1305,
  RFC 7748 for X25519, RFC 8032 for Ed25519).
- Arithmetic coding compression MUST be verified via
  round-trip tests: compress(decompress(x)) == x for all
  valid inputs, with explicit edge-case coverage.
- API integrations MUST use real server endpoints. If an
  external service is unavailable, the feature MUST fail
  explicitly with a clear error—never silently degrade to
  a fake response.
- Feature flags or graceful degradation notices are
  acceptable; silent fake behavior is not.

**Rationale**: A "working" demo that uses mock crypto gives
false confidence and masks integration bugs that surface
only in production under adversarial conditions.

### III. Cryptographic Rigor

All cryptographic implementations MUST follow established
standards and use audited libraries. Rolling custom crypto
is prohibited unless no audited alternative exists for the
target platform, and in that case a formal review is required.

- Key exchange: X3DH protocol using X25519 + Ed25519 keys,
  following the Signal specification.
- Message encryption: ChaCha20-Poly1305 (IETF, 12-byte nonce)
  for server-compatible paths; XChaCha20-Poly1305 (24-byte
  nonce) for offline/local-only paths where nonce collision
  risk is higher.
- Key derivation: HKDF-SHA256 for all derived key material.
- Steganographic encoding: LLM-based arithmetic coding with
  verifiable round-trip (encode → decode = original bits).
- Nonces MUST be cryptographically random or derived from a
  counter-based HKDF stream. Nonce reuse under the same key
  is a critical vulnerability—code MUST enforce uniqueness.
- BouncyCastle (`bcprov-jdk18on`) is the approved provider
  for Ed25519, X25519, and ChaCha20-Poly1305 on Android.
  Google Tink is approved for EncryptedSharedPreferences
  and AEAD wrappers only.

**Rationale**: Cryptographic correctness is binary—partially
correct crypto is broken crypto. Standardized algorithms
with published test vectors eliminate ambiguity.

### IV. Zero-Trust Server Architecture

The server is treated as an untrusted intermediary. No design
MUST rely on server-side secrecy for message confidentiality
or integrity.

- The server MUST NOT receive, store, or log plaintext
  messages or private keys at any point in the message
  lifecycle.
- All message content stored server-side MUST be
  steganographically obfuscated (ciphertext hidden in
  cover text). Raw ciphertext MUST NOT be stored.
- Authentication tokens (JWT) MUST use short-lived access
  tokens (≤24 hours) with refresh token rotation.
- Server-side seed encryption (Fernet) protects stego
  metadata at rest but does NOT substitute for E2EE.
- API responses MUST NOT leak metadata that reveals
  communication patterns beyond what is operationally
  necessary (e.g., exact message timestamps may be
  truncated to reduce timing analysis surface).

**Rationale**: If the server is compromised, an attacker
gains only opaque cover text and encrypted metadata—never
plaintext. This is the fundamental security guarantee.

### V. Reliability & Fault Tolerance

The system MUST handle failures gracefully without data loss,
silent corruption, or security degradation.

- Network failures MUST NOT cause message loss. Unsent
  messages MUST be queued locally and retried with
  exponential backoff.
- Cryptographic operations MUST fail loudly (throw/return
  explicit errors) on invalid input—never return partial
  or malformed output.
- Authentication token expiry MUST trigger automatic
  refresh; if refresh fails, the user MUST be prompted
  to re-authenticate. Silent session drops are prohibited.
- Database migrations (Room on Android, SQLAlchemy on
  server) MUST be backward-compatible or include a
  documented migration path.
- The keyboard IME MUST NOT crash the host application.
  All exceptions in keyboard code paths MUST be caught,
  logged, and surfaced as user-visible error states.

**Rationale**: An unreliable secure messenger trains users
to work around it, undermining the security model.

### VI. Test-First for Security Paths

All security-critical code paths MUST have tests written
and failing before implementation begins.

- Cryptographic primitives: unit tests with published
  test vectors (encrypt/decrypt round-trip, known-answer
  tests).
- E2EE key exchange: integration tests simulating
  Alice↔Bob X3DH handshake with deterministic keys.
- Authentication flows: tests covering registration,
  login, token refresh, expired-token rejection, and
  invalid-credential handling.
- Steganographic round-trip: encode(decode(bits)) == bits
  with coverage for edge-case bit patterns (all zeros,
  all ones, random).
- Compression round-trip: compress(decompress(text)) == text
  for empty strings, single words, max-length messages,
  and Unicode edge cases.
- Tests for security paths MUST NOT use mocked crypto.
  Real cryptographic operations with real keys are required.

**Rationale**: Security bugs discovered post-deployment have
catastrophic cost. Test-first discipline ensures coverage
exists before code ships, and real-crypto tests surface
integration issues that mocks hide.

### VII. Defense in Depth

No single layer is trusted to provide complete protection.
Multiple independent defenses MUST exist at each boundary.

- Transport: TLS 1.2+ for all network communication;
  certificate pinning SHOULD be implemented for the
  production server.
- Application: Input validation on both client and server;
  output encoding to prevent injection attacks.
- Storage: Encryption at rest for all sensitive data
  (Android Keystore, EncryptedSharedPreferences, Fernet
  for server-side seeds).
- Authentication: JWT with HMAC-SHA256 signing; bcrypt
  ($2b$, cost ≥12) for password hashing; rate limiting
  on auth endpoints.
- Code: No secrets in source code, build scripts, or
  version control. All secrets MUST come from environment
  variables or secure vaults.
- Dependencies: Third-party libraries MUST be pinned to
  specific versions. Known-vulnerability scanning (e.g.,
  Dependabot, `safety` for Python, Gradle dependency
  verification) MUST be part of CI.

**Rationale**: Layered defenses ensure that a breach in one
layer (e.g., TLS downgrade, server compromise) does not
cascade to full plaintext exposure.

## Security Requirements & Constraints

### Technology Stack Constraints

| Component | Approved Technology | Constraint |
|-----------|-------------------|------------|
| Android crypto | BouncyCastle `bcprov-jdk18on` 1.79+ | Ed25519, X25519, ChaCha20-Poly1305, HKDF |
| Key storage | Android Keystore + EncryptedSharedPreferences | AES-256-GCM master key |
| Networking | Retrofit 2.9+ / OkHttp 4.12+ | TLS enforced; auth interceptor required |
| Server framework | FastAPI (Python) | Async I/O; Pydantic validation on all endpoints |
| Server DB | PostgreSQL (prod) / SQLite (dev) | SQLAlchemy ORM; Alembic migrations |
| Server auth | JWT HS256 | Access: ≤24h; Refresh: ≤30d with rotation |
| Password storage | bcrypt ($2b$, cost ≥12) | No plaintext, no reversible encryption |
| Steganography | LLM arithmetic coding (Modal API) | MUST degrade gracefully if API unavailable |

### Compliance & Data Handling

- User plaintext MUST never leave the device unencrypted.
- Logs (client and server) MUST NOT contain plaintext
  message content, private keys, or session keys.
- Server logs MAY contain user IDs, timestamps, and
  request metadata for operational purposes.
- Data retention policies MUST be documented and
  enforceable (message expiry, account deletion).
- GDPR and CCPA rights (data export, deletion) MUST be
  supported at the API level.

### Prohibited Practices

- Storing private keys in SharedPreferences without
  encryption.
- Using `Math.random()`, `java.util.Random`, or any
  non-cryptographic PRNG for key material or nonces.
- Hardcoding API keys, JWT secrets, or encryption keys
  in source code.
- Disabling TLS verification in production builds.
- Using `GlobalScope.launch` for coroutines (use
  structured concurrency with `viewModelScope`,
  `lifecycleScope`, or supervised scopes).
- Committing `.env` files, keystore passwords, or
  signing keys to version control.

## Development Workflow & Quality Gates

### Code Review Requirements

- All changes to files in `crypto/`, `core/Crypto*`,
  `services/e2ee*`, `middleware/auth*`, or any file
  containing cryptographic operations MUST receive
  security-focused review.
- Reviewers MUST verify: no hardcoded secrets, proper
  error handling on crypto operations, nonce uniqueness
  enforcement, and test coverage for new code paths.

### Quality Gates (CI Pipeline)

| Gate | Condition | Blocks Merge? |
|------|-----------|--------------|
| Build | Android (debug + release) compiles cleanly | Yes |
| Unit tests | All pass, ≥80% line coverage on crypto modules | Yes |
| Integration tests | E2EE round-trip, auth flow, compression round-trip | Yes |
| Static analysis | Detekt (Kotlin), Ruff/Flake8 (Python) — zero errors | Yes |
| Dependency scan | No known critical/high CVEs in dependencies | Yes |
| Secrets scan | No secrets detected (e.g., `trufflehog`, `gitleaks`) | Yes |
| Server tests | FastAPI test suite passes (`pytest`) | Yes |

### Branching & Versioning

- `main` branch is protected; direct pushes prohibited.
- Feature branches: `<issue-number>-<short-description>`.
- Version format: MAJOR.MINOR.PATCH (SemVer).
  - MAJOR: Breaking API changes, protocol version bumps,
    or cryptographic algorithm changes.
  - MINOR: New features, new endpoints, new keyboard panels.
  - PATCH: Bug fixes, security patches, dependency updates.
- Security patches MUST be fast-tracked and released within
  48 hours of confirmed vulnerability.

## Governance

This constitution is the supreme governance document for the
Secure Keyboard project. All development practices, code
reviews, architectural decisions, and feature implementations
MUST comply with the principles defined herein.

### Amendment Procedure

1. Propose amendment via pull request modifying this file.
2. Amendment MUST include rationale and impact assessment.
3. Version MUST be incremented per SemVer rules
   (see Principle VII / Branching & Versioning).
4. All existing features MUST be audited for compliance
   with amended principles within one sprint of adoption.

### Compliance Review

- Every feature specification (`/specs/*/spec.md`) MUST
  include a Constitution Check section verifying alignment
  with all seven core principles.
- Every implementation plan (`/specs/*/plan.md`) MUST
  pass the Constitution Check gate before Phase 0 research.
- Quarterly security audits MUST review cryptographic
  implementations against current best practices and
  known vulnerabilities.

### Guidance File

Runtime development guidance (technology-specific commands,
project structure, code style) is maintained in the
auto-generated agent guidance file. The constitution defines
principles; the guidance file defines procedures.

**Version**: 1.0.0 | **Ratified**: 2026-02-23 | **Last Amended**: 2026-02-23
