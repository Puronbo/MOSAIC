"""Portable function-tool declaration for the MOSAIC candidate gateway.

The shape follows the widely used chat-completions function-tool convention;
it contains no provider credentials or provider-specific runtime behavior.
"""


def mosaic_candidate_tool() -> dict:
    """Return a fresh JSON-serializable tool declaration for agent registration."""
    return {
        "type": "function",
        "function": {
            "name": "mosaic_verify_candidate",
            "description": (
                "Submit an untrusted mathematical candidate to MOSAIC for "
                "task-bound checking and optional independent Lean verification. "
                "The tool does not generate candidates. Never claim proof unless "
                "the returned status is FORMALLY_VERIFIED."
            ),
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "request": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "schema_version": {
                                "type": "string",
                                "const": "1.0",
                            },
                            "operation": {
                                "type": "string",
                                "enum": [
                                    "simplify", "expand", "factor",
                                    "differentiate", "integrate",
                                    "verify_identity",
                                ],
                            },
                            "expression": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 2000,
                            },
                            "variable": {
                                "type": "string",
                                "minLength": 1,
                                "maxLength": 32,
                            },
                            "rhs": {
                                "type": ["string", "null"],
                                "maxLength": 2000,
                            },
                        },
                        "required": [
                            "schema_version", "operation", "expression",
                            "variable", "rhs",
                        ],
                    },
                    "candidate": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 10000,
                        "description": (
                            "JSON text using the strict task-bound claim schema. "
                            "For identities include operation, expression, rhs. "
                            "For transformations include operation, expression, "
                            "variable, result."
                        ),
                    },
                    "provider_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 80,
                    },
                    "model_id": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 160,
                    },
                },
                "required": [
                    "request", "candidate", "provider_id", "model_id",
                ],
            },
        },
    }
