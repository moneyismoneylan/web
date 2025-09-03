import asyncio
import json
from typing import Callable, Awaitable, List, Dict, Any

try:
    import zmq.asyncio as zasyncio  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    zasyncio = None  # type: ignore


class DistributedOrchestrator:
    """Minimal asyncio/ZeroMQ based orchestrator for agent metrics."""

    def __init__(self, endpoint: str = "inproc://orchestrator", report_file: str = "orchestrator_report.json") -> None:
        self.endpoint = endpoint
        self.report_file = report_file
        self.metrics: List[Dict[str, Any]] = []
        if zasyncio:
            self._ctx = zasyncio.Context.instance()
            self._queue = None
            self._pull = self._ctx.socket(zasyncio.PULL)
            self._pull.bind(self.endpoint)
        else:
            self._ctx = None
            self._queue = asyncio.Queue()
            self._pull = None

    async def send_metric(self, metric: Dict[str, Any]) -> None:
        if zasyncio:
            sock = self._ctx.socket(zasyncio.PUSH)
            sock.connect(self.endpoint)
            await sock.send_json(metric)
        else:
            await self._queue.put(metric)

    async def _listener(self) -> None:
        while True:
            if zasyncio:
                data = await self._pull.recv_json()
            else:
                data = await self._queue.get()
            self.metrics.append(data)

    async def run(self, agents: List[Callable[["DistributedOrchestrator"], Awaitable[None]]], duration: float = 0.1) -> List[Dict[str, Any]]:
        """Run agents and collect metrics for *duration* seconds."""
        listener = asyncio.create_task(self._listener())
        tasks = [asyncio.create_task(a(self)) for a in agents]
        await asyncio.sleep(duration)
        for t in tasks:
            if not t.done():
                t.cancel()
        listener.cancel()
        try:
            await listener
        except asyncio.CancelledError:
            pass
        with open(self.report_file, "w", encoding="utf-8") as f:
            json.dump(self.metrics, f, indent=2)
        return self.metrics
