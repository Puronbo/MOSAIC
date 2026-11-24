# MOSAIC agent orchestration contract (v11.4)

## Purpose

Orchestration coordinates specialized agents without expanding the trusted computing base. Agents are untrusted proposal producers. Their outputs are evidence to inspect, not proof objects.

## Roles

- **Decomposer:** turns a goal into explicit subgoals and dependencies.
- **Solver:** proposes candidate derivations or computations.
- **Critic:** searches for hidden assumptions, invalid steps, edge cases, and counterexamples.
- **Verifier:** identifies the independent checker or proof obligation required. A model playing this role is still not the trusted proof kernel.

## Task contract

Each task has a stable ID, role, bounded goal/context, explicit assumptions, dependency IDs, token budget, and timeout. The task graph must have unique IDs, known dependencies, and no cycles. A deterministic topological order is used so orchestration can be replayed and audited.

## Proposal contract

Every proposal records its task ID, agent ID, role, claim, rationale, assumptions, evidence references, and execution status. Agent output must be treated as untrusted input and validated before use. A provider adapter must enforce independent wall-clock, token, concurrency, and request-size limits; the core contract does not itself enforce runtime isolation.

## Conflict and consensus policy

- No proposals: keep the task pending or mark it incomplete.
- One distinct claim: mark it as a candidate for independent checking.
- Multiple distinct claims: require adversarial review and preserve every proposal. The assessment retains the immutable proposal records in input order, groups proposal indexes by claim, and identifies every proposal participating in a collision.
- Claim grouping collapses presentation whitespace only. It does not case-fold, reorder symbols, simplify expressions, or infer mathematical equivalence; those require a separate sound checker.
- A collision is a review trigger, not proof that either proposal is false. Reviewers must inspect assumptions, derivations, and evidence independently.
- `collision_review_tasks` creates one bounded critic task per conflicting proposal and a synthesis task dependent on all critics. Critic tasks depend on the original task; the synthesis task depends on the original task and every critic.
- The planner enforces a configurable proposal-count budget (16 by default), bounded context size, deterministic task IDs, and graph validation. It creates tasks only; it does not call providers, run reviewers, or treat review output as verification.
- Matching claims from multiple models are not proof and do not increase the mathematical status above `EXPERIMENTAL`.
- A critic's disagreement is a useful signal, not an automatic refutation.
- Only a separate sound checker may establish a mathematical result. Only a configured trusted proof kernel may support `FORMALLY_VERIFIED`.

## Execution lifecycle

`PENDING -> RUNNING -> COMPLETED | FAILED | TIMED_OUT`

Retries must be bounded and recorded as new attempts. Preserve provider/model identifiers, prompt and context hashes, timestamps, resource use, task dependencies, raw outputs, and checker versions. Never silently overwrite a conflicting proposal.

## Deterministic scheduler

`initialize_task_records`, `dispatch_ready_tasks`, `complete_task`, and `fail_task` provide a provider-neutral state machine. The caller supplies a monotonic clock value and invokes its chosen provider adapter outside the core. Dispatch is deterministic, bounded by `max_concurrency`, and only starts tasks whose dependencies are `COMPLETED`. Deadlines transition running tasks to `TIMED_OUT`; retries are bounded by `max_attempts`. Exhausted timeouts and failures remain non-success states and block dependent work. Completion requires a proposal bound to the exact task ID and role. Scheduler records preserve attempt count, start/deadline, proposal, and failure information. This is scheduling state management, not process isolation, provider execution, or mathematical verification.

## Structured review findings and obligation routing

Critic proposals may attach typed `ReviewFinding` records (derivation gap, unsupported assumption, counterexample, evidence required, or unresolved). `assess_completed_reviews` accepts only a complete, exact set of completed critic task records; missing, duplicate, non-critic, or mismatched results are rejected. Only findings explicitly marked as requiring an independent check become `ReviewObligation` records, each retaining the originating task, agent, finding ID, category, statement, and evidence references. Freeform narrative is never parsed into an obligation.

`obligation_verification_tasks` converts those records into deterministic, bounded verifier tasks dependent on both the original task and the originating critic task. It enforces an obligation-count and context-size budget and validates the resulting dependency graph. This is routing of reviewer-suggested checks, not validation that a finding is true or that a verifier has discharged it. Findings may optionally bind to an exact request fingerprint and an allow-listed checker ID. `check_review_obligation_with_lean` runs only the existing request-bound Lean identity checker when both the fingerprint and the registered obligation statement match the supplied immutable `MathRequest`; it never interprets reviewer text as Lean source or a caller-selected proposition. Stale bindings are rejected, and unsupported operations remain unsupported. Checker outcomes and provenance are returned in a structured receipt. The assessment remains `EXPERIMENTAL`; model agreement, review synthesis, and typed labels cannot establish correctness.

## Security boundaries

Treat prompts, model responses, retrieved documents, and tool outputs as untrusted data. Do not allow an agent to choose arbitrary tools or permissions. Use explicit capability allow-lists, secret isolation, egress controls, per-agent quotas, output-size limits, and process isolation for symbolic computation. Redact secrets before logging.

## Current implementation

`mosaic.core.orchestration` provides immutable Pydantic task/proposal/assessment contracts, typed review findings and obligation routing, request-bound checker dispatch, dependency graph validation, and conservative proposal aggregation. Collision assessments preserve the original proposals and expose deterministic claim groups and conflicting proposal indexes; they intentionally do not choose a winner or infer semantic equivalence. `collision_review_tasks` turns those indexes into a bounded, deterministic critic-and-synthesis dependency plan. It does not call model APIs, execute agents, provide provider isolation, or verify mathematics. The scheduler manages state and dispatch eligibility only; provider execution remains an external adapter.


## Integrity-checked verification receipts

The mosaic.verification.receipts module provides an immutable, versioned receipt format for an allow-listed checker result. A receipt binds the outcome to the request fingerprint, checker ID, review obligation, originating task/agent, and finding ID. Its canonical SHA-256 digest covers the complete serialized payload except the digest field itself; replay validates both that digest and the exact request fingerprint before returning the stored record.

Receipt replay does not invoke a provider or checker and does not elevate an outcome. A valid digest is an integrity/provenance check, not a digital signature and not evidence that the mathematical claim is true. A FORMALLY_VERIFIED receipt records that the named trusted checker reported success for the bound request; deployments with a stronger freshness policy must rerun the trusted kernel or validate a separately authenticated kernel artifact. The ReceiptStore supplies local append-only persistence using bounded JSON records, fsynced temporary files, and atomic no-overwrite creation. It validates receipt integrity and request binding on load. The storage directory, backups, access control, host integrity, and writer authentication remain deployment responsibilities; SHA-256 is not a signature. A production multi-host deployment should use an authenticated transactional store with an explicit retention and key-management policy.


For deployments that need writer authentication, `AuthenticatedReceipt` wraps a receipt with an HMAC-SHA256 tag using a caller-managed key of at least 32 bytes. Verification checks the tag and then the receipt digest/request binding. The key must be stored outside the receipt store and rotated/controlled by the deployment; HMAC is shared-secret authentication, not a public signature or proof of checker correctness.


## Scheduler crash-recovery snapshots

The mosaic.core.scheduler_persistence module captures the full task graph and an exact scheduler record for every task. It validates unique IDs, graph acyclicity/dependencies, completed-task proposal presence, and proposal-to-task role/ID binding. Snapshots are canonicalized, size-bounded, SHA-256 checked, and can be persisted locally through an atomic append-only store. Loading restores recorded proposals and task statuses; it does not call providers or automatically dispatch pending/running work. Deployments must define how to reconcile tasks that were RUNNING at process death, because a persisted RUNNING state is not proof that a remote provider stopped or completed. The digest is tamper-evident, not authenticated; protect the store and use a separately authenticated storage layer where required.


`quarantine_interrupted_tasks` applies the conservative restart rule: every persisted RUNNING task becomes FAILED with an explicit unknown-provider-outcome message. It does not retry or mark such work successful. Operators must reconcile the provider outcome before creating a new attempt, avoiding duplicate remote side effects after an ambiguous crash.


Crash recovery quarantines both RUNNING and TIMED_OUT tasks. A timeout does not prove a remote worker stopped, so it is not automatically retried after a restart; downstream tasks remain blocked until the ambiguous outcome is reconciled.



## Receipt coverage and conservative review completion

`assess_receipt_coverage` requires an exact one-to-one match between the review obligations and their stored checker receipts. It revalidates each receipt digest and request fingerprint, then checks the originating task, agent, finding, request hash, and allow-listed checker binding. Missing, duplicate, extra, stale, or cross-wired records are rejected. Non-success checker outcomes remain unresolved rather than being counted as discharged.

Even when every routed obligation has a `FORMALLY_VERIFIED` receipt, the coverage assessment's mathematical status remains `EXPERIMENTAL`. Review findings may cover only part of a claim, and receipt coverage is not a proof of the original task. The gate reports whether the explicitly requested checks were recorded as successful; it does not infer completeness of the mathematical argument or replace trusted-kernel verification of the exact proposition.
