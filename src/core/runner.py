"""Core orchestrator and scoring engine for chaos-qa."""

import asyncio
from dataclasses import dataclass, field
from typing import Any

from src.attacks.payload_fuzzer import PayloadFuzzer, PayloadFuzzerResult
from src.attacks.race_hammer import RaceConditionHammer, RaceHammerResult
from src.attacks.socket_chaos import SocketChaosAttacker, SocketChaosResult


@dataclass
class ChaosReport:
    """Consolidated chaos testing report with resilience score and recommendations."""

    target_url: str
    method: str
    resilience_score: int
    grade: str
    race_result: RaceHammerResult | None = None
    fuzz_result: PayloadFuzzerResult | None = None
    socket_result: SocketChaosResult | None = None
    all_vulnerabilities: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    passed: bool = True


class ChaosRunner:
    """Orchestrator combining race condition, fuzzing, and socket chaos attacks."""

    def __init__(
        self,
        url: str,
        method: str = "POST",
        concurrency: int = 20,
        json_payload: dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 12.0,
    ) -> None:
        self.url = url
        self.method = method.upper()
        self.concurrency = concurrency
        self.json_payload = json_payload or {"amount": 100, "item_id": "test-1"}
        self.headers = headers or {}
        self.timeout = timeout

    async def run_race(self) -> RaceHammerResult:
        """Executes targeted race condition hammer."""
        hammer = RaceConditionHammer(
            url=self.url,
            method=self.method,
            concurrency=self.concurrency,
            headers=self.headers,
            json_data=self.json_payload,
            timeout=self.timeout,
        )
        return await hammer.run()

    async def run_fuzz(self) -> PayloadFuzzerResult:
        """Executes payload fuzzing suite."""
        fuzzer = PayloadFuzzer(
            url=self.url,
            method=self.method,
            json_template=self.json_payload,
            headers=self.headers,
            timeout=self.timeout,
        )
        return await fuzzer.run()

    async def run_socket(self) -> SocketChaosResult:
        """Executes raw TCP socket chaos."""
        attacker = SocketChaosAttacker(
            url=self.url,
            iterations=10,
            timeout=self.timeout,
        )
        return await attacker.run()

    async def run_full_suite(self) -> ChaosReport:
        """Runs all chaos attack vectors sequentially and calculates resilience score."""
        race_res = await self.run_race()
        fuzz_res = await self.run_fuzz()
        socket_res = await self.run_socket()

        return self.generate_report(race_res, fuzz_res, socket_res)

    def generate_report(
        self,
        race_res: RaceHammerResult | None = None,
        fuzz_res: PayloadFuzzerResult | None = None,
        socket_res: SocketChaosResult | None = None,
    ) -> ChaosReport:
        """Computes resilience score and generates actionable recommendations."""
        score = 100
        vulnerabilities: list[str] = []
        recommendations: list[str] = []

        # 1. Evaluate Race Condition Hammer
        if race_res is not None:
            vulnerabilities.extend(race_res.vulnerabilities)
            if race_res.collision_detected:
                score -= 30
                recommendations.append(
                    "Race Condition: Protect critical state transitions with concurrency controls. "
                    "Use database transactions with row locks ('SELECT ... FOR UPDATE'), atomic conditional SQL updates, "
                    "or in-memory 'asyncio.Lock' to prevent duplicate actions or lost updates."
                )
            if race_res.inconsistent_status_codes:
                score -= 20
                recommendations.append(
                    "Concurrency Errors: Catch concurrency conflicts and deadlocks in your handlers, "
                    "returning HTTP 409 Conflict rather than uncaught 500 Internal Server Errors."
                )
            if race_res.latency_spike_ratio > 10.0 and race_res.max_latency_ms > 200.0:
                score -= 10
                recommendations.append(
                    "High Latency Variance: Optimize thread pool / connection pool contention under concurrent bursts."
                )

        # 2. Evaluate Payload Fuzzer
        if fuzz_res is not None:
            vulnerabilities.extend(fuzz_res.vulnerabilities)
            if fuzz_res.crash_500_count > 0:
                penalty = min(35, fuzz_res.crash_500_count * 7)
                score -= penalty
                recommendations.append(
                    "Unhandled Exceptions: Implement request schema validation (e.g. Pydantic v2 / msgspec). "
                    "Handle JSONDecodeError, KeyError, and TypeError gracefully to return HTTP 400 Bad Request or "
                    "HTTP 422 Unprocessable Entity instead of raw HTTP 500."
                )
            if fuzz_res.silent_swallow_200_count > 0:
                penalty = min(20, fuzz_res.silent_swallow_200_count * 4)
                score -= penalty
                recommendations.append(
                    "Missing Validation: Reject empty payloads, negative numbers, and unexpected types with HTTP 400/422. "
                    "Do not silently swallow malformed inputs with HTTP 200 OK."
                )

        # 3. Evaluate Socket Chaos
        if socket_res is not None:
            vulnerabilities.extend(socket_res.vulnerabilities)
            if not socket_res.server_survived:
                score -= 40
                recommendations.append(
                    "Socket Exhaustion / Crash: Handle unexpected TCP EOF and client disconnects "
                    "(e.g. catch asyncio.IncompleteReadError / ClientDisconnect). Ensure socket descriptors and workers "
                    "are not leaked or hung on aborted streams."
                )
            elif socket_res.latency_degradation_pct > 200.0:
                score -= 15
                recommendations.append(
                    "Slow Disconnect Cleanup: Tune server keep-alive timeouts and backlog buffer sizes "
                    "to rapidly recycle connections closed by clients."
                )

        score = max(0, min(100, score))

        # Determine grade
        if score >= 90:
            grade = "A (Bulletproof)"
        elif score >= 75:
            grade = "B (Resilient)"
        elif score >= 50:
            grade = "C (Fragile)"
        elif score >= 25:
            grade = "D (Vulnerable)"
        else:
            grade = "F (Critical Risk)"

        passed = score >= 80 and len(vulnerabilities) == 0

        # If perfectly passed and no recommendations needed
        if not recommendations:
            recommendations.append("Endpoint demonstrated high resilience against concurrency, fuzzing, and socket disruptions.")

        return ChaosReport(
            target_url=self.url,
            method=self.method,
            resilience_score=score,
            grade=grade,
            race_result=race_res,
            fuzz_result=fuzz_res,
            socket_result=socket_res,
            all_vulnerabilities=vulnerabilities,
            recommendations=recommendations,
            passed=passed,
        )
