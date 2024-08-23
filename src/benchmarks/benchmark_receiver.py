import asyncio
import time
import json
from src.log_receiver import handle_client


async def benchmark_receiver(num_logs=1000):
    """
    Benchmark the receiver by sending multiple log entries.

    Args:
        num_logs (int): Number of log messages to send for benchmarking.
    """
    for _ in range(num_logs):
        start_time = time.time()
        # Simulate receiving a log entry
        await handle_client(reader, writer)
        print(f"Processed log in {time.time() - start_time:.6f} seconds")


if __name__ == "__main__":
    asyncio.run(benchmark_receiver(num_logs=1000))
