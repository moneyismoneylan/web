import asyncio
import zmq
import zmq.asyncio as zasyncio
import json

async def main():
    """
    A mock GUI client that subscribes to the orchestrator's real-time
    metric stream and prints the results to the console.
    """
    ctx = zasyncio.Context.instance()
    sub_socket = ctx.socket(zmq.SUB)

    # Connect to the orchestrator's publishing endpoint
    pub_endpoint = "tcp://127.0.0.1:5556"
    sub_socket.connect(pub_endpoint)

    # Subscribe to all messages (empty subscription prefix)
    sub_socket.setsockopt(zmq.SUBSCRIBE, b"")

    print(f"--- Mock GUI Client listening on {pub_endpoint} ---")

    try:
        while True:
            message = await sub_socket.recv_json()
            print("\n[GUI] New metric received:")
            print(json.dumps(message, indent=2))
    except asyncio.CancelledError:
        print("\n--- Mock GUI Client shutting down ---")
    finally:
        sub_socket.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
