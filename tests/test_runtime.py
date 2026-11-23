import asyncio

from mosaic.core.adapters import ModelCapability, ProviderRegistry
from mosaic.core.orchestration import AgentRole, AgentTask
from mosaic.core.runtime import ExecutionStatus, execute_task_graph


class StubProvider:
    def __init__(self, provider_id="stub", output="candidate"):
        self._capability = ModelCapability(
            provider_id=provider_id,
            model_id="stub-v1",
            supported_roles=(AgentRole.DECOMPOSER, AgentRole.SOLVER, AgentRole.CRITIC),
        )
        self.output = output
        self.requests = []

    @property
    def capability(self):
        return self._capability

    async def generate(self, request):
        self.requests.append(request)
        return self.output


def test_graph_executes_in_dependency_order_and_passes_prior_output():
    provider = StubProvider()
    registry = ProviderRegistry()
    registry.register(provider)
    tasks = [
        AgentTask(task_id="solve", role=AgentRole.SOLVER, goal="Solve subproblem", depends_on=("split",)),
        AgentTask(task_id="split", role=AgentRole.DECOMPOSER, goal="Decompose problem"),
    ]

    result = asyncio.run(execute_task_graph(
        tasks, registry, {"split": "stub", "solve": "stub"}
    ))

    assert result.execution_order == ("split", "solve")
    assert all(item.status == ExecutionStatus.COMPLETED for item in result.tasks)
    assert "candidate" in provider.requests[1].prompt
    assert result.mathematical_status == "EXPERIMENTAL"
    assert result.tasks[1].proposal.evidence_refs[0].startswith("prompt-sha256:")


def test_failed_task_blocks_dependents_but_not_independent_tasks():
    failing = StubProvider(provider_id="bad", output="")
    good = StubProvider(provider_id="good", output="independent candidate")
    registry = ProviderRegistry()
    registry.register(failing)
    registry.register(good)
    tasks = [
        AgentTask(task_id="a", role=AgentRole.SOLVER, goal="Will fail"),
        AgentTask(task_id="b", role=AgentRole.SOLVER, goal="Depends on a", depends_on=("a",)),
        AgentTask(task_id="c", role=AgentRole.SOLVER, goal="Independent"),
    ]

    result = asyncio.run(execute_task_graph(
        tasks, registry, {"a": "bad", "b": "good", "c": "good"}
    ))
    statuses = {item.task_id: item.status for item in result.tasks}
    assert statuses == {
        "a": ExecutionStatus.FAILED,
        "b": ExecutionStatus.BLOCKED,
        "c": ExecutionStatus.COMPLETED,
    }


def test_missing_assignment_is_rejected_before_execution():
    registry = ProviderRegistry()
    tasks = [AgentTask(task_id="a", role=AgentRole.SOLVER, goal="Solve")]
    try:
        asyncio.run(execute_task_graph(tasks, registry, {}))
    except ValueError as exc:
        assert "missing provider assignments" in str(exc)
    else:
        raise AssertionError("expected missing assignment error")
