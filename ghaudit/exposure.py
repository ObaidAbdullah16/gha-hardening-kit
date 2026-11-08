"""`ghaudit exposure`: was this repository exposed to a known GitHub Actions supply-chain incident?

Three questions, answered from evidence the repository already has:
1. Do the workflows (and local composite actions) *today* reference an affected action - pinned to a
   malicious commit, or by a tag that was hijacked?
2. Did the workflows reference an affected action *during* an incident window? (git history, local checkout)
3. Did any workflow actually *run* during the window? (GitHub API, with --repo)
It also looks for workflow files planted by the 2025 Shai-Hulud npm worms.

It never contacts the affected actions, never runs workflows and never reads secret values.
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.error
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from .incidents import INCIDENTS, WORM_FILES, Incident
from .model import SEVERITY_ORDER

USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*['"]?([^\s'"#]+)""")
SHA = re.compile(r"^[0-9a-f]{40}$")
WF_DIRS = (".github/workflows", ".github/actions")


@dataclass
class Exposure:
    severity: str        # critical | high | medium | info
    kind: str            # malicious-pin | hijackable-tag | sha-pin | used-during-window | runs-during-window | worm-file
    incident: str
    file: str
    line: int
    message: str

    def to_dict(self) -> dict:
        return asdict(self)


def references(text: str) -> list[tuple[int, str, str]]:
    """(line, owner/repo, ref) for every `uses: owner/repo[/path]@ref` in a workflow or action file."""
    out = []
    for i, ln in enumerate(text.splitlines(), start=1):
        m = USES.match(ln)
        if not m or "@" not in m.group(1) or m.group(1).startswith(("./", "docker://")):
            continue
        target, ref = m.group(1).rsplit("@", 1)
        parts = target.split("/")
        if len(parts) >= 2:
            out.append((i, f"{parts[0]}/{parts[1]}".lower(), ref))
    return out


def _incident_for(action: str) -> Incident | None:
    return next((inc for inc in INCIDENTS if action in (a.lower() for a in inc.actions)), None)


def _window_text(inc: Incident) -> str:
    return " and ".join(f"{a:%Y-%m-%d %H:%M}-{b:%H:%M} UTC" if a.date() == b.date() else f"{a:%Y-%m-%d} to {b:%Y-%m-%d} UTC"
                        for a, b in inc.windows)


def scan_files(files: dict[str, str]) -> list[Exposure]:
    """Current state: references to affected actions and planted worm workflows."""
    found: list[Exposure] = []
    for path, text in sorted(files.items()):
        for line, action, ref in references(text):
            inc = _incident_for(action)
            if not inc:
                continue
            if ref.lower() in inc.malicious_shas:
                found.append(Exposure("critical", "malicious-pin", inc.id, path, line,
                                      f"`{action}@{ref[:12]}` is pinned to the MALICIOUS commit from {inc.name}. "
                                      f"Remove it now, treat every secret this workflow can read as stolen, and rotate."))
            elif SHA.match(ref.lower()) and not inc.pin_protects:
                found.append(Exposure("medium", "sha-pin", inc.id, path, line,
                                      f"`{action}` is pinned, but pinning did not protect against {inc.name}: the action fetched "
                                      f"the compromised code itself. Only runs during {_window_text(inc)} matter - check them."))
            elif SHA.match(ref.lower()):
                found.append(Exposure("info", "sha-pin", inc.id, path, line,
                                      f"`{action}` is pinned to a commit SHA. Check it is not one created during {_window_text(inc)} "
                                      f"(safe: {inc.safe})."))
            else:
                found.append(Exposure("high", "hijackable-tag", inc.id, path, line,
                                      f"`{action}@{ref}` uses a tag; during {inc.name} ({_window_text(inc)}) {inc.affected_refs}. "
                                      f"Pin to a reviewed SHA of {inc.safe}, and check runs in that window."))
        name = Path(path).name
        for marker, needle, why in WORM_FILES:
            hit = name.startswith(marker) if marker.endswith("_") else name == marker
            if hit and (needle is None or needle.lower() in text.lower()):
                found.append(Exposure("critical", "worm-file", "SHAI-HULUD", path, 1,
                                      f"{why}. Delete it in a reviewed commit, remove any self-hosted runner named SHA1HULUD, "
                                      f"rotate GitHub, npm and cloud credentials, and review the audit log."))
    return found


def local_files(root: str, workflows_dir: str | None = None) -> dict[str, str]:
    base = Path(root)
    out = {}
    for d in ([workflows_dir] if workflows_dir else WF_DIRS):
        for f in sorted((base / d).rglob("*")) if (base / d).is_dir() else []:
            if f.is_file() and f.suffix in (".yml", ".yaml"):
                out[str(f.relative_to(base))] = f.read_text(encoding="utf-8", errors="replace")
    return out


def _git(root: str, *args: str) -> str:
    return subprocess.run(["git", "-C", root, *args], capture_output=True, text=True, check=True).stdout


def files_at(root: str, when: datetime) -> tuple[str, dict[str, str]]:
    """Workflow and action files as they were on the default branch at `when` ("" if the repo did not exist)."""
    commit = _git(root, "rev-list", "-1", f"--before={when.isoformat()}", "HEAD").strip()
    if not commit:
        return "", {}
    names = _git(root, "ls-tree", "-r", "--name-only", commit, "--", *WF_DIRS).split()
    out = {}
    for n in names:
        if n.endswith((".yml", ".yaml")):
            out[n] = _git(root, "show", f"{commit}:{n}")
    return commit, out


def scan_history(root: str) -> list[Exposure]:
    """Which affected actions the default branch referenced at the start and end of each incident window."""
    found: list[Exposure] = []
    try:
        _git(root, "rev-parse", "--git-dir")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return found
    seen: set[tuple[str, str, str]] = set()
    for inc in INCIDENTS:
        for start, end in inc.windows:
            for moment in (start, end):
                commit, files = files_at(root, moment)
                for path, text in files.items():
                    for line, action, ref in references(text):
                        if action not in (a.lower() for a in inc.actions) or (inc.id, path, ref) in seen:
                            continue
                        seen.add((inc.id, path, ref))
                        bad = ref.lower() in inc.malicious_shas or not SHA.match(ref.lower())
                        found.append(Exposure(
                            "high" if bad else "medium", "used-during-window", inc.id, path, line,
                            f"On {moment:%Y-%m-%d} (commit {commit[:8]}) `{path}` used `{action}@{ref[:12]}` - inside the "
                            f"{inc.name} window ({_window_text(inc)}). Any run of this workflow then could leak: {inc.stole}. "
                            "Check the runs in that window; rotate every secret it could read if one ran."))
    return found


def scan_runs(repo: str, client, incidents: set[str]) -> list[Exposure]:
    """Count workflow runs created during the windows of incidents that touched this repository."""
    found: list[Exposure] = []
    for inc in INCIDENTS:
        if inc.id not in incidents:
            continue
        for start, end in inc.windows:
            span = f"{start:%Y-%m-%dT%H:%M:%SZ}..{end:%Y-%m-%dT%H:%M:%SZ}"
            try:
                data = client.get(f"/repos/{repo}/actions/runs?created={span}&per_page=1")
            except urllib.error.HTTPError as e:
                found.append(Exposure("info", "runs-during-window", inc.id, "-", 0,
                                      f"Could not list runs for {span} (HTTP {e.code}); check Actions logs by hand."))
                continue
            n = int(data.get("total_count", 0)) if isinstance(data, dict) else 0
            if n:
                found.append(Exposure("critical", "runs-during-window", inc.id, "-", 0,
                                      f"{n} workflow run(s) were created during {_window_text(inc)}. Read those logs for the "
                                      "affected step; if it ran, treat its secrets as stolen and follow the rotation plan."))
            else:
                found.append(Exposure("info", "runs-during-window", inc.id, "-", 0,
                                      f"No workflow runs were created during {span}: no run could have leaked secrets then."))
    return found


def sort_key(e: Exposure) -> tuple:
    return (-SEVERITY_ORDER.get(e.severity, 0), e.incident, e.file, e.line)


def to_text(name: str, found: list[Exposure]) -> str:
    lines = [f"ghaudit exposure  repository: {name}  incidents known: {len(INCIDENTS)} + Shai-Hulud worm files", ""]
    for e in sorted(found, key=sort_key):
        loc = f"{e.file}:{e.line}" if e.line else e.file
        lines.append(f"[{e.severity.upper():8}] {e.incident:17} {loc}  {e.message}")
    if not any(e.severity in ("critical", "high", "medium") for e in found):
        lines.append("No exposure found to the known incidents.")
    lines += ["", "Incidents checked:"] + [f"  {i.id:17} {i.name} ({_window_text(i)}) - {i.reference}" for i in INCIDENTS]
    return "\n".join(lines)


def to_markdown(name: str, found: list[Exposure]) -> str:
    out = [f"## Incident exposure check: `{name}`", ""]
    worst = [e for e in found if e.severity in ("critical", "high")]
    out.append(f"**{len(worst)} critical/high item(s).**" if worst else "**No critical or high exposure found.**")
    out += ["", "| Severity | Incident | Where | Finding |", "|---|---|---|---|"]
    for e in sorted(found, key=sort_key):
        out.append(f"| {e.severity} | {e.incident} | `{e.file}:{e.line}` | {e.message} |")
    out += ["", "### Incidents checked", ""]
    out += [f"- **{i.id}** {i.name} - {_window_text(i)} - safe: {i.safe} - [advisory]({i.reference})" for i in INCIDENTS]
    out += ["", "Next steps for anything critical or high: `docs/secrets-addon.md` (rotation plan) and "
            "`docs/incident-exposure-checklist.md`."]
    return "\n".join(out) + "\n"


def to_json(name: str, found: list[Exposure]) -> str:
    return json.dumps({"tool": "ghaudit exposure", "repository": name,
                       "incidents": [i.id for i in INCIDENTS],
                       "findings": [e.to_dict() for e in sorted(found, key=sort_key)]}, indent=2)
