"""Payload fuzzer attack module for AI-generated HTTP endpoints."""

import asyncio
from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any

import httpx


class FuzzClassification(str, Enum):
    """Classification of server reactions to mutated inputs."""

    HANDLED_4XX = "HANDLED_4XX"
    CRASH_500 = "CRASH_500"
    SILENT_SWALLOW_200 = "SILENT_SWALLOW_200"
    UNKNOWN = "UNKNOWN"


@dataclass
class FuzzMutation:
    """A generated payload mutation with descriptive metadata."""

    name: str
    category: str
    description: str
    raw_content: str | None = None
    json_data: Any = None
    is_raw_string: bool = False


@dataclass
class FuzzItemResult:
    """Outcome of sending a single mutated payload."""

    mutation: FuzzMutation
    classification: FuzzClassification
    status_code: int
    response_body: str
    latency_ms: float
    error: str | None = None


@dataclass
class PayloadFuzzerResult:
    """Aggregated results of the payload fuzzing suite."""

    target_url: str
    method: str
    total_mutations: int
    handled_4xx_count: int
    crash_500_count: int
    silent_swallow_200_count: int
    handled_items: list[FuzzItemResult] = field(default_factory=list)
    crash_items: list[FuzzItemResult] = field(default_factory=list)
    swallowed_items: list[FuzzItemResult] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    passed: bool = True


class PayloadFuzzer:
    """Generates malformed and boundary JSON payloads to expose unhandled crashes and missing validation."""

    def __init__(
        self,
        url: str,
        method: str = "POST",
        json_template: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.url = url
        self.method = method.upper()
        self.json_template = json_template if json_template is not None else {"input": "test", "amount": 100}
        self.headers = headers or {}
        self.timeout = timeout

    def generate_mutations(self) -> list[FuzzMutation]:
        """Creates an array of mutated payloads based on the template."""
        mutations: list[FuzzMutation] = []

        # 1. Syntactically broken JSON
        syntax_cases = [
            ("syntax_unclosed_object", "Unclosed JSON object", '{"foo": "bar", '),
            ("syntax_invalid_trailing_comma", "Trailing comma syntax error", '{"items": [1, 2, ], }'),
            ("syntax_unquoted_keys", "Unquoted keys", "{unquoted_key: 123}"),
            ("syntax_truncated_string", "Truncated string literal", '{"key": "truncated value'),
            ("syntax_raw_nan", "Non-standard NaN constant", '{"value": NaN}'),
            ("syntax_random_garbage", "Arbitrary non-JSON string", "<xml>not_json</xml>"),
        ]
        for name, desc, raw in syntax_cases:
            mutations.append(
                FuzzMutation(
                    name=name,
                    category="syntax_broken_json",
                    description=desc,
                    raw_content=raw,
                    is_raw_string=True,
                )
            )

        # 2. Empty or minimal body
        mutations.append(
            FuzzMutation(
                name="empty_body_string",
                category="empty_body",
                description="Completely empty request body",
                raw_content="",
                is_raw_string=True,
            )
        )
        mutations.append(
            FuzzMutation(
                name="empty_object",
                category="empty_body",
                description="Empty JSON dictionary {}",
                json_data={},
            )
        )
        mutations.append(
            FuzzMutation(
                name="empty_array",
                category="empty_body",
                description="Empty JSON array []",
                json_data=[],
            )
        )

        # 3. Type substitutions and field-level mutations
        if isinstance(self.json_template, dict):
            # Entire root type replacement
            mutations.append(
                FuzzMutation(
                    name="root_array_instead_of_object",
                    category="type_substitution",
                    description="Array passed instead of expected JSON object",
                    json_data=[1, 2, 3],
                )
            )
            mutations.append(
                FuzzMutation(
                    name="root_primitive_instead_of_object",
                    category="type_substitution",
                    description="Primitive integer passed instead of JSON object",
                    json_data=12345,
                )
            )

            # Per-key mutations
            for key, val in self.json_template.items():
                # String substitution for numbers
                if isinstance(val, (int, float)):
                    mutations.append(
                        FuzzMutation(
                            name=f"type_str_for_num_{key}",
                            category="type_substitution",
                            description=f"String substituted for numeric field '{key}'",
                            json_data={**self.json_template, key: "not_a_number"},
                        )
                    )
                    mutations.append(
                        FuzzMutation(
                            name=f"negative_num_{key}",
                            category="negative_numbers",
                            description=f"Negative value for numeric field '{key}'",
                            json_data={**self.json_template, key: -999999},
                        )
                    )
                    mutations.append(
                        FuzzMutation(
                            name=f"null_for_num_{key}",
                            category="type_substitution",
                            description=f"Null substituted for numeric field '{key}'",
                            json_data={**self.json_template, key: None},
                        )
                    )
                    mutations.append(
                        FuzzMutation(
                            name=f"array_for_num_{key}",
                            category="type_substitution",
                            description=f"Array substituted for numeric field '{key}'",
                            json_data={**self.json_template, key: [1, 2, 3]},
                        )
                    )

                # Number or object substitution for strings
                if isinstance(val, str):
                    mutations.append(
                        FuzzMutation(
                            name=f"type_num_for_str_{key}",
                            category="type_substitution",
                            description=f"Number substituted for string field '{key}'",
                            json_data={**self.json_template, key: 999999},
                        )
                    )
                    mutations.append(
                        FuzzMutation(
                            name=f"null_for_str_{key}",
                            category="type_substitution",
                            description=f"Null substituted for string field '{key}'",
                            json_data={**self.json_template, key: None},
                        )
                    )
                    mutations.append(
                        FuzzMutation(
                            name=f"object_for_str_{key}",
                            category="type_substitution",
                            description=f"Object substituted for string field '{key}'",
                            json_data={**self.json_template, key: {"nested": True}},
                        )
                    )

                # Null byte injection
                mutations.append(
                    FuzzMutation(
                        name=f"null_byte_{key}",
                        category="special_characters",
                        description=f"Null byte injected into field '{key}'",
                        json_data={**self.json_template, key: "admin\x00extra"},
                    )
                )

                # Oversized / giant string
                mutations.append(
                    FuzzMutation(
                        name=f"giant_string_{key}",
                        category="giant_strings",
                        description=f"50KB string injected into field '{key}'",
                        json_data={**self.json_template, key: "A" * 50000},
                    )
                )

                # Injection probes / formatting chars
                mutations.append(
                    FuzzMutation(
                        name=f"injection_probes_{key}",
                        category="special_characters",
                        description=f"Injection probes injected into field '{key}'",
                        json_data={**self.json_template, key: "' OR '1'='1; -- %s%x %n"},
                    )
                )

        return mutations

    async def run(self) -> PayloadFuzzerResult:
        """Executes all fuzz mutations against the target endpoint and classifies responses."""
        mutations = self.generate_mutations()
        handled_items: list[FuzzItemResult] = []
        crash_items: list[FuzzItemResult] = []
        swallowed_items: list[FuzzItemResult] = []
        vulnerabilities: list[str] = []

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for mutation in mutations:
                req_headers = {"Content-Type": "application/json", **self.headers}
                start_time = asyncio.get_event_loop().time()

                try:
                    if mutation.is_raw_string:
                        response = await client.request(
                            self.method,
                            self.url,
                            headers=req_headers,
                            content=mutation.raw_content or "",
                        )
                    else:
                        response = await client.request(
                            self.method,
                            self.url,
                            headers=req_headers,
                            json=mutation.json_data,
                        )

                    latency = (asyncio.get_event_loop().time() - start_time) * 1000
                    status = response.status_code
                    text = response.text[:500]
                    err = None
                except Exception as exc:
                    latency = (asyncio.get_event_loop().time() - start_time) * 1000
                    status = 0
                    text = ""
                    err = str(exc)

                # Classify reaction
                if 400 <= status < 500:
                    classification = FuzzClassification.HANDLED_4XX
                elif 500 <= status < 600 or (status == 0 and err and "500" in err):
                    classification = FuzzClassification.CRASH_500
                elif 200 <= status < 300:
                    classification = FuzzClassification.SILENT_SWALLOW_200
                else:
                    classification = FuzzClassification.UNKNOWN

                item_result = FuzzItemResult(
                    mutation=mutation,
                    classification=classification,
                    status_code=status,
                    response_body=text,
                    latency_ms=latency,
                    error=err,
                )

                if classification == FuzzClassification.HANDLED_4XX:
                    handled_items.append(item_result)
                elif classification == FuzzClassification.CRASH_500:
                    crash_items.append(item_result)
                elif classification == FuzzClassification.SILENT_SWALLOW_200:
                    swallowed_items.append(item_result)

        # Formulate vulnerabilities
        if crash_items:
            crash_names = [item.mutation.name for item in crash_items[:5]]
            vulnerabilities.append(
                f"Unhandled exceptions (HTTP 500) triggered by {len(crash_items)} mutations: {', '.join(crash_names)}."
            )

        if swallowed_items:
            swallowed_names = [item.mutation.name for item in swallowed_items[:5]]
            vulnerabilities.append(
                f"Silent swallowing (HTTP 200) without input validation on {len(swallowed_items)} invalid payloads: {', '.join(swallowed_names)}."
            )

        passed = len(crash_items) == 0 and len(swallowed_items) == 0

        return PayloadFuzzerResult(
            target_url=self.url,
            method=self.method,
            total_mutations=len(mutations),
            handled_4xx_count=len(handled_items),
            crash_500_count=len(crash_items),
            silent_swallow_200_count=len(swallowed_items),
            handled_items=handled_items,
            crash_items=crash_items,
            swallowed_items=swallowed_items,
            vulnerabilities=vulnerabilities,
            passed=passed,
        )
