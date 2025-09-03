import asyncio
import json
import uuid
from typing import Callable, Awaitable, List, Dict, Any

try:
    import zmq
    import zmq.asyncio as zasyncio
except ImportError:
    zmq = None
    zasyncio = None

try:
    import ray
except ImportError:
    ray = None

class MockFirecrackerManager:
    """Simulates the lifecycle management of Firecracker microVMs."""
    def __init__(self, num_vms: int = 4):
        self._pool = [f"192.168.1.{100 + i}" for i in range(num_vms)]
        self._vms: Dict[str, Dict[str, Any]] = {}

    def provision_vm(self) -> Dict[str, Any] | None:
        if not self._pool:
            print("[Warning] No available microVMs in pool.")
            return None
        vm_id, ip = str(uuid.uuid4())[:8], self._pool.pop(0)
        vm_info = {"id": vm_id, "ip": ip, "state": "running"}
        self._vms[vm_id] = vm_info
        print(f"[Firecracker] Provisioned microVM {vm_id} at {ip}")
        return vm_info

    async def run_task_in_vm(self, vm_id: str, agent_func: Callable, orchestrator):
        if vm_id not in self._vms: raise ValueError(f"VM {vm_id} not found.")
        print(f"[Firecracker] Starting agent in microVM {vm_id}...")
        await agent_func(orchestrator)
        print(f"[Firecracker] Agent finished in microVM {vm_id}.")

    def deprovision_vm(self, vm_id: str):
        if vm_id in self._vms:
            ip = self._vms[vm_id]["ip"]
            self._pool.append(ip)
            del self._vms[vm_id]
            print(f"[Firecracker] Deprovisioned microVM {vm_id}. IP {ip} returned to pool.")

if ray:
    @ray.remote
    class MetricCollector:
        """A Ray actor to collect and incrementally report metrics."""
        def __init__(self, report_file: str):
            self.metrics = []
            self.report_file = report_file
        def add_metric(self, metric: Dict[str, Any]):
            self.metrics.append(metric)
            with open(self.report_file, "w") as f:
                json.dump(self.metrics, f, indent=2)
        def get_metrics(self) -> List[Dict[str, Any]]:
            return self.metrics

class DistributedOrchestrator:
    """Orchestrator for agent metrics with real-time publishing."""
    PUB_ENDPOINT = "tcp://127.0.0.1:5556"

    def __init__(self, backend: str = 'zmq', report_file: str = "orchestrator_report.json") -> None:
        if backend not in ['zmq', 'ray']: raise ValueError("Backend must be 'zmq' or 'ray'")
        if backend == 'ray' and not ray: raise ImportError("Ray backend selected but ray is not installed.")
        if backend == 'zmq' and not zasyncio: raise ImportError("ZMQ backend selected but pyzmq is not installed.")

        self.backend = backend
        self.report_file = report_file
        self.metrics: List[Dict[str, Any]] = []
        self.firecracker_manager = MockFirecrackerManager()

        self._ctx = zasyncio.Context.instance()
        self.pub_socket = self._ctx.socket(zmq.PUB)
        self.pub_socket.bind(self.PUB_ENDPOINT)

        if self.backend == 'ray':
            if not ray.is_initialized(): ray.init(ignore_reinit_error=True, log_to_driver=False)
            self.metric_collector = MetricCollector.remote(self.report_file)
        else: # ZMQ
            self._pull = self._ctx.socket(zmq.PULL)
            self.endpoint = "inproc://orchestrator"
            self._pull.bind(self.endpoint)

    async def send_metric(self, metric: Dict[str, Any]) -> None:
        await self.pub_socket.send_json(metric)
        if self.backend == 'ray':
            await self.metric_collector.add_metric.remote(metric)
        else:
            push = self._ctx.socket(zmq.PUSH)
            push.connect(self.endpoint)
            await push.send_json(metric)
            push.close()

    async def _listener(self) -> None:
        if self.backend == 'zmq':
            while True:
                try:
                    data = await self._pull.recv_json()
                    self.metrics.append(data)
                    with open(self.report_file, "w") as f:
                        json.dump(self.metrics, f, indent=2)
                except asyncio.CancelledError:
                    break

    async def run(self, agents: List[Callable[["DistributedOrchestrator"], Awaitable[None]]]) -> List[Dict[str, Any]]:
        listener_task = asyncio.create_task(self._listener()) if self.backend == 'zmq' else None

        async def run_agent_in_vm(agent_func):
            vm_info = self.firecracker_manager.provision_vm()
            if not vm_info: return
            try:
                await self.firecracker_manager.run_task_in_vm(vm_info['id'], agent_func, self)
            finally:
                self.firecracker_manager.deprovision_vm(vm_info['id'])

        agent_tasks = [ray.remote(agent).remote for agent in agents] if self.backend == 'ray' else agents
        await asyncio.gather(*[run_agent_in_vm(agent) for agent in agent_tasks])

        if listener_task:
            await asyncio.sleep(0.1)
            listener_task.cancel()
            try: await listener_task
            except asyncio.CancelledError: pass

        if self.backend == 'ray':
            self.metrics = await self.metric_collector.get_metrics.remote()
            ray.shutdown()

        self.pub_socket.close()
        return self.metrics
