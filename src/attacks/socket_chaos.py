"""Raw TCP socket chaos attacker to test unexpected EOF and connection drops."""

import asyncio
from dataclasses import dataclass, field
import time
from urllib.parse import urlsplit

import httpx


@dataclass
class SocketChaosResult:
    """Outcome of socket chaos attacks."""

    target_url: str
    host: str
    port: int
    abrupt_disconnects_sent: int
    server_survived: bool
    baseline_latency_ms: float
    post_attack_latency_ms: float
    latency_degradation_pct: float
    details: list[str] = field(default_factory=list)
    vulnerabilities: list[str] = field(default_factory=list)
    passed: bool = True


class SocketChaosAttacker:
    """Opens raw TCP connections, sends truncated/broken HTTP headers and abruptly closes sockets."""

    def __init__(
        self,
        url: str,
        iterations: int = 8,
        timeout: float = 5.0,
    ) -> None:
        self.url = url
        self.iterations = max(1, iterations)
        self.timeout = timeout

        parsed = urlsplit(url)
        self.host = parsed.hostname or "127.0.0.1"
        if self.host == "localhost":
            self.host = "127.0.0.1"
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.path = parsed.path or "/"

    async def _measure_health_latency(self) -> tuple[bool, float]:
        """Checks if server responds and records latency in ms."""
        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                res = await client.get(self.url)
                latency = (time.perf_counter() - start_time) * 1000
                return True, latency
        except Exception:
            # Try HEAD or base URL if GET to specific endpoint failed
            try:
                base_url = f"{urlsplit(self.url).scheme}://{self.host}:{self.port}/"
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    await client.get(base_url)
                    latency = (time.perf_counter() - start_time) * 1000
                    return True, latency
            except Exception:
                return False, 0.0

    async def _send_broken_tcp_stream(self, payload: bytes) -> None:
        """Opens raw connection, sends partial bytes and abruptly closes writer."""
        reader = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=self.timeout,
            )
            if payload:
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), timeout=1.0)
            # Abrupt unexpected EOF: close writer without waiting for server response
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            pass
        finally:
            if writer is not None:
                try:
                    writer.close()
                except Exception:
                    pass

    async def run(self) -> SocketChaosResult:
        """Executes raw TCP chaos burst and verifies server stability."""
        details: list[str] = []
        vulnerabilities: list[str] = []

        # 1. Measure baseline latency
        survived_baseline, baseline_lat = await self._measure_health_latency()
        if not survived_baseline:
            return SocketChaosResult(
                target_url=self.url,
                host=self.host,
                port=self.port,
                abrupt_disconnects_sent=0,
                server_survived=False,
                baseline_latency_ms=0.0,
                post_attack_latency_ms=0.0,
                latency_degradation_pct=0.0,
                details=["Target server is unreachable before starting chaos attack."],
                vulnerabilities=["Endpoint unreachable."],
                passed=False,
            )

        details.append(f"Baseline latency established: {baseline_lat:.2f} ms")

        # 2. Prepare truncated payload patterns
        patterns = [
            # Incomplete headers
            f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\nContent-Type: application/json\r\nContent-Len".encode(),
            # Declared large Content-Length followed by immediate EOF
            f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\nContent-Length: 10000\r\n\r\nshort".encode(),
            # Abrupt chunked encoding truncation
            f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello".encode(),
            # Zero-byte immediate EOF
            b"",
            # Partial request line
            f"GET {self.path[:3]}".encode(),
        ]

        # 3. Fire socket chaos iterations
        sent_count = 0
        for i in range(self.iterations):
            pattern = patterns[i % len(patterns)]
            await self._send_broken_tcp_stream(pattern)
            sent_count += 1
            await asyncio.sleep(0.01)

        details.append(f"Dispatched {sent_count} abrupt TCP EOF/half-open socket disruptions.")

        # 4. Check post-attack availability
        survived_post, post_lat = await self._measure_health_latency()

        if not survived_post:
            vulnerabilities.append(
                "Server crashed or stopped accepting connections after abrupt TCP socket disconnections (unexpected EOF)."
            )
            return SocketChaosResult(
                target_url=self.url,
                host=self.host,
                port=self.port,
                abrupt_disconnects_sent=sent_count,
                server_survived=False,
                baseline_latency_ms=round(baseline_lat, 2),
                post_attack_latency_ms=0.0,
                latency_degradation_pct=999.0,
                details=details,
                vulnerabilities=vulnerabilities,
                passed=False,
            )

        degradation_pct = 0.0
        if baseline_lat > 0:
            degradation_pct = max(0.0, round(((post_lat - baseline_lat) / baseline_lat) * 100, 2))

        if degradation_pct > 250.0 and post_lat > 200.0:
            vulnerabilities.append(
                f"Significant latency degradation after socket teardown: +{degradation_pct}% ({post_lat:.2f} ms vs {baseline_lat:.2f} ms baseline)."
            )

        details.append(
            f"Server survived. Post-attack latency: {post_lat:.2f} ms (degradation: {degradation_pct:+.1f}%)."
        )

        passed = survived_post and len(vulnerabilities) == 0

        return SocketChaosResult(
            target_url=self.url,
            host=self.host,
            port=self.port,
            abrupt_disconnects_sent=sent_count,
            server_survived=survived_post,
            baseline_latency_ms=round(baseline_lat, 2),
            post_attack_latency_ms=round(post_lat, 2),
            latency_degradation_pct=degradation_pct,
            details=details,
            vulnerabilities=vulnerabilities,
            passed=passed,
        )
