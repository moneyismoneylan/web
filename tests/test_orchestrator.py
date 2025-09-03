import asyncio
import json
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from distributed_orchestrator import DistributedOrchestrator


def test_orchestrator_collects_metrics(tmp_path):
    report = tmp_path / "report.json"

    async def agent(o: DistributedOrchestrator):
        await o.send_metric({"v": 1})

    orchestrator = DistributedOrchestrator(report_file=str(report))
    metrics = asyncio.run(orchestrator.run([agent]))
    assert metrics == [{"v": 1}]
    data = json.loads(report.read_text())
    assert data == [{"v": 1}]
