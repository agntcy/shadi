#!/usr/bin/env python3
# Copyright AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""Minimal demo agent for the SHADI interactive shell walkthrough.

This script simulates a long-running agent process so you can attach
to it from ``shadictl shell`` and exercise policy query/patch commands
in real time.

Usage (standalone):
    python3 examples/shell_demo/demo_agent.py

Usage (sandboxed with control socket):
    cargo run -p shadictl -- \\
        --profile balanced --read ~/.pyenv --watch-policy \\
        -- python3 examples/shell_demo/demo_agent.py

Then in a second terminal:
    cargo run -p shadictl -- shell
    /sessions          # discover the control socket
    /attach <socket>   # or copy the path from the first terminal
    /policy query      # inspect the sandbox policy
    /policy patch --add-allow-command npm
    /policy query      # verify the patch was applied

Note: on macOS with pyenv, add ``--read ~/.pyenv`` so the sandbox can
      find the Python binary.  The bash demo script
      (examples/shell_demo/demo_agent.sh) avoids this requirement.
"""

import os
import signal
import sys
import time

TICK_INTERVAL = int(os.environ.get("DEMO_TICK", "3"))


def main():
    print("[demo-agent] starting — press Ctrl-C to stop", flush=True)
    print(f"[demo-agent] pid={os.getpid()}", flush=True)
    print(f"[demo-agent] cwd={os.getcwd()}", flush=True)
    print(f"[demo-agent] tick every {TICK_INTERVAL}s", flush=True)
    print(flush=True)

    # Handle SIGTERM gracefully so shadictl can clean up.
    def _term(signum, frame):
        print("\n[demo-agent] received SIGTERM — shutting down", flush=True)
        sys.exit(0)

    signal.signal(signal.SIGTERM, _term)

    tick = 0
    try:
        while True:
            tick += 1
            ts = time.strftime("%H:%M:%S")
            print(f"[demo-agent] tick {tick:>4}  {ts}", flush=True)
            time.sleep(TICK_INTERVAL)
    except KeyboardInterrupt:
        print("\n[demo-agent] interrupted — shutting down", flush=True)


if __name__ == "__main__":
    main()
