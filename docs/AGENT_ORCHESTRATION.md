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

## Security boundaries

Treat prompts, model responses, retrieved documents, and tool outputs as untrusted data. Do not allow an agent to choose arbitrary tools or permissions. Use explicit capability allow-lists, secret isolation, egress controls, per-agent quotas, output-size limits, and process isolation for symbolic computation. Redact secrets before logging.

## Current implementation

`mosaic.core.orchestration` provides immutable Pydantic task/proposal/assessment contracts, dependency graph validation, and conservative proposal aggregation. Collision assessments preserve the original proposals and expose deterministic claim groups and conflicting proposal indexes; they intentionally do not choose a winner or infer semantic equivalence. `collision_review_tasks` turns those indexes into a bounded, deterministic critic-and-synthesis dependency plan. It does not call model APIs, execute agents, provide provider isolation, or verify mathematics. The scheduler manages state and dispatch eligibility only; provider execution remains an external adapter.
