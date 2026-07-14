# SecretSweep Testable Build Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a safe, searchable, selectable cleanup CLI first, then expose that tested local engine through a zero-custody agent and self-hosted reference stack.

**Architecture:** The Go CLI owns all plaintext repository data and produces an immutable cleanup plan before mutation. A later customer-side agent will serialize only encrypted control envelopes; Temporal orchestrates durable jobs, AutoMQ distributes status/audit facts, and PostgreSQL remains the control-plane system of record. The community profile runs on one Docker host, while the production profile uses three private nodes.

**Tech Stack:** Go 1.26, Bubble Tea/Bubbles/Lip Gloss, Git, git-filter-repo, Docker Compose, PostgreSQL, Temporal, AutoMQ, RustFS-compatible S3 storage, OpenBao, OpenTelemetry.

## Global Constraints

- No raw secret may appear in terminal output, logs, workflow payloads, event messages, database records, or tests.
- Nothing is selected by default in the interactive review screen.
- Selecting a recovered secret applies its replacement across every discovered repository.
- Delete-file removes the selected repository-relative path from that repository's history and replaces the same secret everywhere else.
- Replacement defaults to `REMOVED_API_KEY` and must be non-empty, single-line, syntactically safe, and different from every selected compromised secret.
- Every destructive run requires an exact preview and typed confirmation.
- Tests must be written and observed failing before production code is added.
- The OSS edition must run without Cloud Run; Cloud Run is an optional hosted control-plane deployment.

---

### Task 1: Pure Review and Cleanup Plan Model

**Files:**
- Create: `secretsweep/review.go`
- Create: `secretsweep/review_test.go`
- Modify: `secretsweep/trivy.go`

**Interfaces:**
- Consumes: `Finding` from `trivy.go`.
- Produces: `Finding.StableID() string`, `ReviewState`, `ReviewAction`, `CleanupPlan`, `BuildCleanupPlan(ReviewState) (CleanupPlan, error)`, and `ValidateReplacement(string, []string) error`.

- [ ] Write table-driven failing tests proving stable IDs contain no secret, search is case-insensitive, navigation is bounded, selection defaults empty, replacement groups the same secret globally, delete paths are repository-scoped, and invalid replacements are rejected.
- [ ] Run `go test ./... -run 'Test(Stable|Review|BuildCleanup|ValidateReplacement)'` and confirm failures are caused by missing behavior.
- [ ] Implement the minimal immutable plan model and validation.
- [ ] Run the focused tests and then `go test ./...`.

### Task 2: Plan-Aware Git Rewrite Engine

**Files:**
- Modify: `secretsweep/engine.go`
- Create: `secretsweep/engine_test.go`

**Interfaces:**
- Consumes: `CleanupPlan` from Task 1.
- Produces: `RunCleanupPlan(io.Writer, EngineAction, CleanupPlan, []string) int`, repository-specific filter-repo arguments, and secure replacement-rule files.

- [ ] Write failing tests for per-repository delete arguments, global replacements, masked dry-run output, dirty-tree refusal, replacement-file permissions, and scan/dry-run exit statuses using temporary real Git repositories.
- [ ] Run `go test ./... -run 'Test(RunCleanup|FilterRepo|ReplacementFile)'` and verify the expected failures.
- [ ] Implement plan execution while retaining `RunEngine` as a compatibility wrapper for headless operation.
- [ ] Run focused tests, `go test -race ./...`, and `go vet ./...`.

### Task 3: Searchable Split-Pane TUI

**Files:**
- Modify: `secretsweep/tui.go`
- Modify: `secretsweep/tui_test.go`

**Interfaces:**
- Consumes: `ReviewState`, `CleanupPlan`, and `RunCleanupPlan`.
- Produces: keyboard-driven search, selection/action cycling, replacement editing, plan preview, confirmation, and progress views.

- [ ] Write failing model tests for `/` search, escape/back behavior, next/previous navigation, empty default selection, action cycling, editable replacement, preview gating, typed confirmation, preserved selection after filtering, and scan finding-count feedback.
- [ ] Run `go test ./... -run 'TestTUI|TestScan|TestEngineStreams'` and verify failures.
- [ ] Implement a responsive split pane: coloured action/status table on the left and selected-finding details/help on the right.
- [ ] Stream scan progress with total findings and a safe latest-finding label; never render raw secret text.
- [ ] Run focused tests and render snapshot-style assertions at narrow and wide terminal sizes.

### Task 4: Headless Contract and Documentation

**Files:**
- Modify: `secretsweep/main.go`
- Create: `secretsweep/main_test.go`
- Modify: `README.md`
- Modify: `Makefile`

**Interfaces:**
- Produces: `--replacement`, deterministic dry-run output, documented exit codes, and CI-friendly test/build targets.

- [ ] Write failing tests for argument validation and safe headless plan construction.
- [ ] Implement the flags without changing existing exit-code meanings.
- [ ] Document all interactive keys, destructive-action semantics, and recovery steps.
- [ ] Run `make check`, `go test -race ./...`, and `go build ./...`.

### Task 5: Encrypted Zero-Custody Agent Protocol

**Files:**
- Create: `internal/protocol/envelope.go`
- Create: `internal/protocol/envelope_test.go`
- Create: `cmd/secretsweep-agent/main.go`
- Create: `cmd/secretsweep-agent/main_test.go`

**Interfaces:**
- Produces: versioned command/result envelopes with tenant, agent, job, nonce, expiry, ciphertext, signature, and idempotency key fields.
- Consumes: serialized cleanup-plan hashes, never raw findings or replacement strings.

- [ ] Write failing cryptographic round-trip, tamper, expiry, replay-key, and serialization tests using generated test keys.
- [ ] Implement envelope encryption with an authenticated standard-library construction and separate signing keys.
- [ ] Implement an outbound-only polling agent shell whose local executor calls the tested cleanup engine.
- [ ] Prove protocol JSON and logs do not contain the test secret using negative assertions.

### Task 6: Fully Self-Hosted Development Profile

**Files:**
- Create: `deploy/compose/docker-compose.yml`
- Create: `deploy/compose/.env.example`
- Create: `deploy/compose/README.md`
- Create: `deploy/compose/scripts/healthcheck.sh`
- Create: `deploy/compose/tests/compose_test.go`

**Interfaces:**
- Produces: a single-host stack containing the control API, PostgreSQL, Temporal, AutoMQ dependencies, S3-compatible storage, OpenBao, and OpenTelemetry endpoints on private Docker networks.

- [ ] Write failing configuration tests that parse the Compose model and reject public stateful ports, floating image tags, missing health checks, writable root filesystems where avoidable, and plaintext default credentials.
- [ ] Add the minimum pinned Compose profile and generated-secret bootstrap instructions.
- [ ] Run configuration tests and `docker compose config`; when Docker is available, start the stack and run the health check.

### Task 7: Three-Node Production Profile

**Files:**
- Create: `deploy/production/README.md`
- Create: `deploy/production/compose.node.yml`
- Create: `deploy/production/config/`
- Create: `deploy/production/tests/production_config_test.go`

**Interfaces:**
- Produces: private three-node configurations for Temporal, AutoMQ, Patroni/PostgreSQL, etcd, S3-compatible object storage, OpenBao Raft, and observability.

- [ ] Write failing topology tests for quorum membership, private listeners, TLS requirements, dedicated volumes, CPU/memory limits, backup targets, and anti-affinity documentation.
- [ ] Implement the converged low-cost topology with explicit upgrade paths to split node pools.
- [ ] Exercise one-node-loss, database promotion, workflow continuation, broker restart, and backup-restore runbooks in disposable VMs.

### Task 8: Hosted Control Plane and Release Gates

**Files:**
- Create: `cmd/secretsweep-api/`
- Create: `internal/controlplane/`
- Create: `deploy/cloudrun/`
- Create: `.github/workflows/ci.yml`
- Modify: `CHANGE_REPORT.md`

**Interfaces:**
- Produces: authenticated command leasing, PostgreSQL transactional outbox, Temporal workflow adapters, AutoMQ status publishing, SBOMs, signed images, and reproducible releases.

- [ ] Write failing API tests for tenant isolation, idempotent command leases, replay refusal, outbox atomicity, authorization, and ciphertext-only storage.
- [ ] Implement the smallest control API and adapters behind interfaces so unit tests require no external services.
- [ ] Add container/integration tests for PostgreSQL, Temporal, and AutoMQ, plus a complete agent-to-control-plane smoke test.
- [ ] Run unit, race, integration, security, restore, and build verification before committing and pushing `codex/distributed-secure-service`.

## Self-Review

- Spec coverage: CLI usability, colours, progress, discovery feedback, search/navigation, selection, replacement, delete-file history removal, preview/confirmation, zero custody, self-hosted Temporal/AutoMQ, Docker, Cloud Run option, encryption, low-cost tiers, enterprise isolation, and testing all map to tasks above.
- Placeholder scan: every task names concrete behavior, files, interfaces, and verification commands; no deferred implementation placeholders are present.
- Type consistency: the local `CleanupPlan` produced in Task 1 is executed in Task 2, driven by Task 3/4, hashed locally by Task 5, and never serialized as plaintext by Tasks 5/8.
