"""Reproducible timing of in-memory synthetic auth analysis; not a production benchmark."""
import argparse
import json
from datetime import datetime, timedelta, timezone
from time import perf_counter

from workbench import investigate


def generated_events(count):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [{"timestamp": start + timedelta(seconds=i * 3),
             "username": f"demo.user{i % 80}",
             "source_ip": f"192.0.2.{(i % 200) + 1}",
             "event": "failure" if i % 5 else "success"} for i in range(count)]


def benchmark(sizes=(1000, 5000, 10000), repetitions=3):
    if repetitions < 1 or any(size < 1 or size > 100_000 for size in sizes):
        raise ValueError("Use 1-100000 events and at least one repetition")
    rows = []
    for size in sizes:
        events = generated_events(size)
        timings = []
        report = None
        for _ in range(repetitions):
            started = perf_counter()
            report = investigate(events)
            timings.append((perf_counter() - started) * 1000)
        rows.append({"events": size, "median_ms": round(sorted(timings)[len(timings)//2], 3),
                     "findings": len(report["findings"])})
    return {"benchmark": "Synthetic in-memory data only; machine-dependent wall-clock timings", "results": rows}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", type=int, nargs="+", default=[1000, 5000, 10000])
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        output = json.dumps(benchmark(args.sizes, args.repetitions), indent=2)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as stream:
                stream.write(output + "\n")
        print(output)
    except ValueError as exc:
        parser.error(str(exc))
