"""Network path to the host via the system traceroute. Opt-in because it is slow."""

from __future__ import annotations

import asyncio
import re
import shutil
import sys

from webaudit.checks.base import register
from webaudit.context import CheckSkipped, SiteContext
from webaudit.models import CheckResult, Severity

MAX_HOPS = 20
_HOP = re.compile(r"^\s*(\d+)\s+(.+)$")
_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,}\b", re.I)
_RTT = re.compile(r"<?(\d+(?:\.\d+)?)\s*ms")


def build_command(host: str) -> list[str] | None:
    if sys.platform == "win32":
        tool, args = "tracert", ["-d", "-h", str(MAX_HOPS), "-w", "1000"]
    else:
        tool, args = "traceroute", ["-n", "-m", str(MAX_HOPS), "-w", "1"]
    path = shutil.which(tool)
    return [path, *args, host] if path else None


def parse_output(text: str) -> list[dict]:
    hops = []
    for line in text.splitlines():
        match = _HOP.match(line)
        if not match:
            continue
        body = match.group(2)
        rtts = [float(value) for value in _RTT.findall(body)]
        without_rtts = _RTT.sub(" ", body)
        ip = _IP.search(without_rtts)
        hops.append(
            {
                "hop": int(match.group(1)),
                "ip": ip.group(0) if ip else None,
                "rtt_ms": rtts,
            }
        )
    return hops


@register("traceroute", "Network path to the host (slow; enable with --traceroute)", default=False)
async def run(ctx: SiteContext, result: CheckResult) -> None:
    command = build_command(ctx.target.host)
    if command is None:
        raise CheckSkipped("no traceroute tool found on this system")

    process = await asyncio.create_subprocess_exec(
        *command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        stdout, _ = await process.communicate()
    finally:
        # Reached on timeout too, so a stuck traceroute never outlives its check.
        if process.returncode is None:
            process.kill()
            await process.wait()

    hops = parse_output(stdout.decode("utf-8", errors="replace"))
    result.data["hops"] = hops
    if not hops or hops[-1]["ip"] is None:
        result.add(
            Severity.INFO,
            "Traceroute did not reach the host",
            "Many networks drop traceroute probes, so this alone isn't a fault.",
        )
