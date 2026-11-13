"""Race condition hammer attack module using asyncio.Barrier and httpx."""

import asyncio
from collections import Counter
from dataclasses import dataclass, field
import json
import statistics
import time
from typing import Any

import httpx


@dataclass
class RaceHammerResult:
    """Results from running a race condition hammer attack."""

    target_url: str
    method: str
    concurrency: int
    total_requests: int
    successful_requests: int
    failed_requests: int
    status_distribution: dict[int, int]
    latencies_ms: list[float]
    min_latency_ms: float
    max_latency_ms: float
    avg_latency_ms: float
    latency_spike_ratio: float
    collision_detected: bool
    inconsistent_status_codes: bool
    vulnerabilities: list[str] = field(default_factory=list)
    passed: bool = True
    raw_responses: list[dict[str, Any]] = field(default_factory=list)


class RaceConditionHammer:
    """Fires simultaneous identical requests using asyncio.Barrier to expose race conditions."""

    def __init__(
        self,
        url: str,
        method: str = "POST",
        concurrency: int = 20,
        headers: dict[str, str] | None = None,
        json_data: dict[str, Any] | list[Any] | None = None,
        data: str | None = None,
        timeout: float = 15.0,
    ) -> None:
        self.url = url
        self.method = method.upper()
        self.concurrency = max(2, concurrency)
        self.headers = headers or {}
        self.json_data = json_data
        self.data = data
        self.timeout = timeout

    async def run(self) -> RaceHammerResult:
        """Executes the concurrent burst and analyzes the responses."""
        barrier = asyncio.Barrier(self.concurrency)
        limits = httpx.Limits(
            max_connections=self.concurrency + 10,
            max_keepalive_connections=self.concurrency + 10,
        )

        results: list[dict[str, Any]] = []

        async with httpx.AsyncClient(limits=limits, timeout=self.timeout) as client:

            async def _worker(worker_id: int) -> dict[str, Any]:
                try:
                    # Synchronize all coroutines to fire at the exact same moment
                    await barrier.wait()
                    start_time = time.perf_counter()

                    req_kwargs: dict[str, Any] = {
                        "headers": self.headers,
                    }
                    if self.json_data is not None:
                        req_kwargs["json"] = self.json_data
                    elif self.data is not None:
                        req_kwargs["content"] = self.data

                    response = await client.request(self.method, self.url, **req_kwargs)
                    latency = (time.perf_counter() - start_time) * 1000

                    body_json = None
                    try:
                        body_json = response.json()
                    except Exception:
                        body_json = None

                    return {
                        "worker_id": worker_id,
                        "status_code": response.status_code,
                        "latency_ms": latency,
                        "text": response.text,
                        "json": body_json,
                        "error": None,
                    }
                except Exception as exc:
                    return {
                        "worker_id": worker_id,
                        "status_code": 0,
                        "latency_ms": 0.0,
                        "text": "",
                        "json": None,
                        "error": str(exc),
                    }

            tasks = [_worker(i) for i in range(self.concurrency)]
            results = await asyncio.gather(*tasks)

        return self._analyze_results(results)

    def _analyze_results(self, raw_results: list[dict[str, Any]]) -> RaceHammerResult:
        """Analyzes response codes, latencies, collisions, and state inconsistencies."""
        status_codes = [r["status_code"] for r in raw_results if r["status_code"] > 0]
        distribution = dict(Counter(status_codes))
        latencies = sorted([r["latency_ms"] for r in raw_results if r["latency_ms"] > 0])

        total_requests = len(raw_results)
        successful_requests = sum(1 for code in status_codes if 200 <= code < 300)
        failed_requests = total_requests - successful_requests

        min_lat = round(latencies[0], 2) if latencies else 0.0
        max_lat = round(latencies[-1], 2) if latencies else 0.0
        avg_lat = round(statistics.mean(latencies), 2) if latencies else 0.0
        spike_ratio = round(max_lat / (min_lat if min_lat > 0.01 else 0.1), 2)

        vulnerabilities: list[str] = []
        inconsistent_status_codes = False
        collision_detected = False

        # 1. Inconsistent status codes analysis
        has_2xx = any(200 <= c < 300 for c in status_codes)
        has_5xx = any(500 <= c < 600 for c in status_codes)
        has_4xx = any(400 <= c < 500 for c in status_codes)

        if has_2xx and has_5xx:
            inconsistent_status_codes = True
            vulnerabilities.append(
                f"Inconsistent statuses detected under concurrency: "
                f"{distribution.get(500, 0)} requests crashed with 5xx while {successful_requests} succeeded with 2xx."
            )
        elif has_5xx:
            inconsistent_status_codes = True
            vulnerabilities.append(
                f"Server crashed with 5xx under {self.concurrency} concurrent requests ({distribution})."
            )

        # 2. Collision / state inconsistency detection
        # Check for duplicated IDs / tokens in successful JSON bodies
        seen_ids: dict[str, list[int]] = {}
        extracted_balances: list[float] = []

        for r in raw_results:
            j = r.get("json")
            if isinstance(j, dict):
                # Check for common identifier collisions
                for id_field in ("id", "uuid", "order_id", "transaction_id", "token"):
                    if id_field in j and j[id_field] is not None:
                        key = f"{id_field}:{j[id_field]}"
                        seen_ids.setdefault(key, []).append(r["worker_id"])

                # Check for balance / counter corruption
                for bal_field in ("balance", "remaining", "count", "stock"):
                    if bal_field in j and isinstance(j[bal_field], (int, float)):
                        extracted_balances.append(float(j[bal_field]))

        # Flag duplicated identifiers across distinct concurrent requests
        for id_val, worker_ids in seen_ids.items():
            if len(worker_ids) > 1:
                collision_detected = True
                vulnerabilities.append(
                    f"Duplicate identifier collision: {id_val} returned by {len(worker_ids)} concurrent requests."
                )

        # Flag balance corruption (negative balance or identical balance values across multiple deductions)
        if extracted_balances:
            if any(b < 0 for b in extracted_balances):
                collision_detected = True
                vulnerabilities.append(
                    f"Race condition in balance/counter: negative value detected ({min(extracted_balances)})."
                )
            # If multiple requests succeeded with the exact same updated balance value
            balance_counts = Counter(extracted_balances)
            duplicate_balances = [b for b, count in balance_counts.items() if count > 1]
            if duplicate_balances and successful_requests > 1:
                collision_detected = True
                vulnerabilities.append(
                    f"Lost update race condition: identical state returned across concurrent updates ({duplicate_balances})."
                )

        # 3. Latency spike analysis
        if spike_ratio > 10.0 and max_lat > 200.0:
            vulnerabilities.append(
                f"Significant latency spike detected: {spike_ratio}x increase (min: {min_lat}ms, max: {max_lat}ms)."
            )

        passed = not collision_detected and not inconsistent_status_codes and len(vulnerabilities) == 0

        return RaceHammerResult(
            target_url=self.url,
            method=self.method,
            concurrency=self.concurrency,
            total_requests=total_requests,
            successful_requests=successful_requests,
            failed_requests=failed_requests,
            status_distribution=distribution,
            latencies_ms=latencies,
            min_latency_ms=min_lat,
            max_latency_ms=max_lat,
            avg_latency_ms=avg_lat,
            latency_spike_ratio=spike_ratio,
            collision_detected=collision_detected,
            inconsistent_status_codes=inconsistent_status_codes,
            vulnerabilities=vulnerabilities,
            passed=passed,
            raw_responses=raw_results,
        )
