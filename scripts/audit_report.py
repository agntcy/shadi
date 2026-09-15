#!/usr/bin/env python3
"""Render `cargo audit --json` as GitHub annotations and a job summary.

`cargo audit` exits non-zero and leaves the detail in the log, so a failing
check says only "Audit fail" until someone opens the run and scrolls. This
turns each advisory into an inline annotation and a summary table, and says
whether a fixed release exists — an advisory we can patch today and one
pinned shut by the dependency graph are not the same failure.
"""

import json
import os
import sys


def emit(line: str) -> None:
    print(line, flush=True)


def summary(rows: list[str]) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as fh:
        fh.write("\n".join(rows) + "\n")


def main() -> int:
    try:
        with open(sys.argv[1], encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError) as err:
        emit(f"::error::cargo audit produced no usable JSON report: {err}")
        return 1

    vulns = (report.get("vulnerabilities") or {}).get("list") or []
    warnings = report.get("warnings") or {}

    rows = ["## cargo audit"]
    if not vulns:
        rows.append("")
        rows.append("No vulnerabilities.")
    else:
        rows.append("")
        rows.append("| advisory | crate | version | fixed in |")
        rows.append("| --- | --- | --- | --- |")

    for item in vulns:
        advisory = item.get("advisory") or {}
        package = item.get("package") or {}
        patched = (item.get("versions") or {}).get("patched") or []
        ident = advisory.get("id", "?")
        name = package.get("name", "?")
        version = package.get("version", "?")
        fixed = ", ".join(patched) if patched else "no fixed release"
        title = advisory.get("title", "")

        emit(f"::error title={ident} ({name} {version})::{title} — fixed in {fixed}")
        rows.append(f"| [{ident}](https://rustsec.org/advisories/{ident}) | {name} | {version} | {fixed} |")

    warn_total = sum(len(v) for v in warnings.values())
    if warn_total:
        rows.append("")
        rows.append(f"<details><summary>{warn_total} non-failing warnings</summary>")
        rows.append("")
        for kind, items in sorted(warnings.items()):
            for item in items:
                package = item.get("package") or {}
                advisory = item.get("advisory") or {}
                rows.append(
                    f"- `{package.get('name','?')} {package.get('version','?')}`"
                    f" — {kind}: {advisory.get('id','')}"
                )
        rows.append("")
        rows.append("</details>")

    summary(rows)
    noun = "vulnerability" if len(vulns) == 1 else "vulnerabilities"
    emit(f"{len(vulns)} {noun}, {warn_total} warnings")
    return 1 if vulns else 0


if __name__ == "__main__":
    sys.exit(main())
