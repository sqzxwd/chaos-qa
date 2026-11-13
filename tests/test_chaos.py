"""End-to-end tests for chaos-qa with intentional AI code vulnerabilities."""

import asyncio
import json
import threading
from typing import Any, Generator

import pytest
from typer.testing import CliRunner

from src.attacks.payload_fuzzer import FuzzClassification, PayloadFuzzer
from src.attacks.race_hammer import RaceConditionHammer
from src.attacks.socket_chaos import SocketChaosAttacker
from src.cli import app
from src.core.runner import ChaosRunner


class VulnerableTestServer:
    """Async HTTP server implementing intentional vulnerabilities typical of AI-generated code."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self.server: asyncio.Server | None = None
        self.balance = 100
        self.withdrawal_count = 0

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            request_line = await reader.readline()
            if not request_line:
                writer.close()
                await writer.wait_closed()
                return

            line_str = request_line.decode("latin1", errors="replace").strip()
            parts = line_str.split()
            if len(parts) < 2:
                writer.close()
                await writer.wait_closed()
                return

            method, path = parts[0], parts[1]

            # Read headers
            headers: dict[str, str] = {}
            content_length = 0
            while True:
                header_line = await reader.readline()
                if not header_line or header_line in (b"\r\n", b"\n"):
                    break
                h_decoded = header_line.decode("latin1", errors="replace").strip()
                if ":" in h_decoded:
                    k, v = h_decoded.split(":", 1)
                    k_clean = k.strip().lower()
                    headers[k_clean] = v.strip()
                    if k_clean == "content-length":
                        try:
                            content_length = int(v.strip())
                        except ValueError:
                            content_length = 0

            # Read body if specified
            body = b""
            if content_length > 0:
                body = await reader.readexactly(content_length)

            status_code = 200
            resp_data: dict[str, Any] | str = {}

            # Route handling
            if path == "/health":
                resp_data = {"status": "ok"}

            elif path == "/withdraw":
                # VULNERABILITY 1: RACE CONDITION (Non-atomic balance deduction without lock)
                current = self.balance
                # Artificial context switch window exposing lost updates under concurrency
                await asyncio.sleep(0.015)
                self.balance = current - 10
                self.withdrawal_count += 1
                resp_data = {
                    "balance": self.balance,
                    "withdrawal_id": self.withdrawal_count,
                    "status": "success",
                }

            elif path == "/api/order":
                # VULNERABILITY 2: UNHANDLED 500 CRASH ON INVALID JSON / MISSING FIELDS
                try:
                    raw_str = body.decode("utf-8")
                    parsed = json.loads(raw_str)
                    # Missing type validation: assumes parsed is dict with numeric "amount"
                    total = parsed["amount"] + 10
                    resp_data = {"order_id": 101, "total": total, "status": "created"}
                except Exception as exc:
                    # AI-style unhandled failure manifesting as 500
                    status_code = 500
                    resp_data = {"error": str(exc), "type": type(exc).__name__}

            elif path == "/api/swallow":
                # VULNERABILITY 3: SILENT SWALLOW 200 (No validation at all)
                resp_data = {"status": "accepted"}

            else:
                status_code = 404
                resp_data = {"error": "not found"}

            body_bytes = json.dumps(resp_data).encode("utf-8")
            response_header = (
                f"HTTP/1.1 {status_code} OK\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(body_bytes)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("latin1")

            writer.write(response_header + body_bytes)
            await writer.drain()

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> str:
        """Starts server and binds to an ephemeral local port."""
        self.server = await asyncio.start_server(self.handle_client, self.host, 0)
        sock = self.server.sockets[0]
        self.port = sock.getsockname()[1]
        return f"http://{self.host}:{self.port}"

    async def stop(self) -> None:
        """Gracefully shuts down the server."""
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class ThreadedAsyncServer:
    """Runs VulnerableTestServer inside a background thread with an independent event loop."""

    def __init__(self) -> None:
        self.server = VulnerableTestServer()
        self.thread: threading.Thread | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.base_url: str = ""

    def start(self) -> tuple[VulnerableTestServer, str]:
        ready_event = threading.Event()

        def _worker() -> None:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)

            async def _init_server() -> None:
                self.base_url = await self.server.start()
                ready_event.set()

            self.loop.run_until_complete(_init_server())
            self.loop.run_forever()

        self.thread = threading.Thread(target=_worker, daemon=True)
        self.thread.start()
        ready_event.wait(timeout=5.0)
        return self.server, self.base_url

    def stop(self) -> None:
        if self.loop and self.server.server:
            future = asyncio.run_coroutine_threadsafe(self.server.stop(), self.loop)
            try:
                future.result(timeout=5.0)
            except Exception:
                pass
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread:
            self.thread.join(timeout=2.0)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def test_server() -> Generator[tuple[VulnerableTestServer, str], None, None]:
    threaded = ThreadedAsyncServer()
    server, base_url = threaded.start()
    try:
        yield server, base_url
    finally:
        threaded.stop()


@pytest.mark.anyio
async def test_race_condition_hammer_detects_collision(test_server):
    server, base_url = test_server
    withdraw_url = f"{base_url}/withdraw"

    hammer = RaceConditionHammer(
        url=withdraw_url,
        method="POST",
        concurrency=15,
        json_data={"amount": 10},
    )
    result = await hammer.run()

    # Verify race hammer executed concurrent requests
    assert result.concurrency == 15
    assert result.total_requests == 15
    # The intentional sleep causes lost updates: identical balance returned across requests
    assert result.collision_detected is True
    assert result.passed is False
    assert len(result.vulnerabilities) > 0
    assert any("race condition" in v.lower() or "lost update" in v.lower() for v in result.vulnerabilities)


@pytest.mark.anyio
async def test_payload_fuzzer_detects_500_crashes(test_server):
    server, base_url = test_server
    order_url = f"{base_url}/api/order"

    fuzzer = PayloadFuzzer(
        url=order_url,
        method="POST",
        json_template={"amount": 100},
    )
    result = await fuzzer.run()

    # Verify mutations triggered 500 unhandled exceptions in the vulnerable server
    assert result.total_mutations > 0
    assert result.crash_500_count > 0
    assert result.passed is False
    assert len(result.crash_items) > 0
    assert any(item.classification == FuzzClassification.CRASH_500 for item in result.crash_items)
    assert any("Unhandled exceptions (HTTP 500)" in v for v in result.vulnerabilities)


@pytest.mark.anyio
async def test_socket_chaos_attacker(test_server):
    server, base_url = test_server
    health_url = f"{base_url}/health"

    attacker = SocketChaosAttacker(url=health_url, iterations=6)
    result = await attacker.run()

    assert result.abrupt_disconnects_sent == 6
    assert result.server_survived is True
    assert result.baseline_latency_ms >= 0.0
    assert result.post_attack_latency_ms >= 0.0
    assert result.passed is True


@pytest.mark.anyio
async def test_chaos_runner_scoring_and_recommendations(test_server):
    server, base_url = test_server
    # Test runner against the endpoint that crashes on bad input
    runner = ChaosRunner(
        url=f"{base_url}/api/order",
        method="POST",
        concurrency=10,
        json_payload={"amount": 50},
    )
    report = await runner.run_full_suite()

    # Score should be degraded below 100 due to fuzz crashes
    assert report.resilience_score < 100
    assert report.fuzz_result is not None
    assert report.fuzz_result.crash_500_count > 0
    # Remediation recommendations must be present and actionable
    assert len(report.recommendations) > 0
    assert any("validation" in r.lower() or "pydantic" in r.lower() for r in report.recommendations)


def test_cli_race_and_fuzz_commands(test_server):
    # Test CLI execution via Typer CliRunner
    server, base_url = test_server
    runner = CliRunner()

    # 1. Test CLI race command on vulnerable endpoint
    race_res = runner.invoke(app, ["race", f"{base_url}/withdraw", "--concurrency", "10"])
    assert race_res.exit_code == 1  # Exit code 1 due to detected race condition
    assert "Race Condition Attack Analysis" in race_res.stdout
    assert "DETECTED" in race_res.stdout

    # 2. Test CLI fuzz command on vulnerable endpoint
    fuzz_res = runner.invoke(app, ["fuzz", f"{base_url}/api/order", "--json", '{"amount": 10}'])
    assert fuzz_res.exit_code == 1  # Exit code 1 due to 500 crashes
    assert "Payload Fuzzing Classification" in fuzz_res.stdout
    assert "CRASH_500" in fuzz_res.stdout

    # 3. Test CLI attack full suite command
    attack_res = runner.invoke(app, ["attack", f"{base_url}/withdraw", "--concurrency", "8"])
    assert attack_res.exit_code == 1
    assert "Resilience Evaluation" in attack_res.stdout
    assert "Concrete Remediation Steps" in attack_res.stdout
