import asyncio
from sqli_hunter.scanner import DistributedScanner


def test_distributed_scanner_queue():
    received = []

    async def run():
        ds = DistributedScanner("inproc://unit-test")

        async def handler(msg):
            received.append(msg)
            # stop after first message
            task.cancel()

        task = asyncio.create_task(ds.worker(handler))
        await asyncio.sleep(0.01)
        await ds.submit({"id": 1})
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run())
    assert received == [{"id": 1}]
