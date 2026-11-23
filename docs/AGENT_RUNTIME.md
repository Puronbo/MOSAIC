# Deterministic agent graph execution

MOSAIC's first execution runner connects the task graph and provider adapter
contracts without changing the trust model.

## Flow

1. Validate unique task IDs, known dependencies, and acyclicity.
2. Require an explicit provider assignment for every task.
3. Execute tasks in stable topological order.
4. Include completed dependency proposals as structured, untrusted input.
5. Record provider/model identity, proposal text, and prompt/output hashes.
6. Mark failed tasks and block only their dependents; independent tasks continue.

The runner is sequential and deterministic. It does not yet provide parallel
scheduling, retries, durable storage, live provider implementations, or
independent mathematical verification. Provider output is always an
experimental proposal. Hashes support provenance and integrity checks; they
do not establish correctness.
