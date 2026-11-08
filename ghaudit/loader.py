"""Load workflow files from a local folder or a GitHub repository."""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import yaml

from .model import RepoContext, WorkflowFile


def _normalise(data: Any) -> dict[str, Any]:
    """PyYAML follows YAML 1.1, so the key `on:` is read as boolean True. Fix that."""
    if not isinstance(data, dict):
        return {}
    if True in data and "on" not in data:
        data["on"] = data.pop(True)
    return data


def _index_lines(node: Any, path: tuple[Any, ...], out: dict[tuple[Any, ...], int]) -> None:
    """Record the line of every mapping key and list item. Searching the raw text for a string
    would find the *first* occurrence, which is often the wrong one (a job ID also used as an
    input name, the same expression in an `env:` line and in a `run:` script...)."""
    out.setdefault(path, node.start_mark.line + 1)
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            k = key.value if isinstance(key, yaml.ScalarNode) else str(key.value)
            out.setdefault(path + (k,), key.start_mark.line + 1)
            _index_lines(value, path + (k,), out)
    elif isinstance(node, yaml.SequenceNode):
        for i, item in enumerate(node.value):
            out.setdefault(path + (i,), item.start_mark.line + 1)
            _index_lines(item, path + (i,), out)


def parse_workflow(path: str, text: str) -> WorkflowFile:
    wf = WorkflowFile(path=path, text=text)
    try:
        wf.data = _normalise(yaml.safe_load(text) or {})
        root = yaml.compose(text)
        if root is not None:
            _index_lines(root, (), wf.node_lines)
    except yaml.YAMLError as e:
        wf.parse_error = str(e).splitlines()[0]
    return wf


def _dependabot_covers_actions(text: str) -> bool:
    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return False
    if not isinstance(data, dict):
        return False
    for upd in data.get("updates", []) or []:
        if isinstance(upd, dict) and upd.get("package-ecosystem") == "github-actions":
            return True
    return False


RENOVATE_FILES = ["renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".github/renovate.json", ".github/renovate.json5"]


def load_local(root: str, workflows_dir: str | None = None) -> RepoContext:
    """Load a repo folder. `workflows_dir` overrides where workflows live (used for the before/after examples)."""
    base = Path(root)
    wdir = Path(workflows_dir) if workflows_dir else base / ".github" / "workflows"
    files: list[WorkflowFile] = []
    if wdir.is_dir():
        for f in sorted(list(wdir.glob("*.yml")) + list(wdir.glob("*.yaml"))):
            try:
                rel = str(f.relative_to(base))
            except ValueError:
                rel = str(f)
            files.append(parse_workflow(rel, f.read_text(encoding="utf-8")))
    dep = False
    for name in ("dependabot.yml", "dependabot.yaml"):
        p = (wdir.parent if workflows_dir else base / ".github") / name
        if p.exists():
            dep = dep or _dependabot_covers_actions(p.read_text(encoding="utf-8"))
    ren = any((base / f).exists() for f in RENOVATE_FILES)
    return RepoContext(name=base.resolve().name, workflows=files, has_dependabot_actions=dep, has_renovate=ren)


class GitHubClient:
    def __init__(self, token: str | None = None, api: str | None = None):
        self.token = token or os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        self.api = api or os.environ.get("GITHUB_API_URL", "https://api.github.com")

    def get(self, path: str) -> Any:
        req = urllib.request.Request(f"{self.api}{path}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", "ghaudit")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode())

    def file_text(self, repo: str, path: str) -> str | None:
        try:
            data = self.get(f"/repos/{repo}/contents/{path}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            raise
        if isinstance(data, dict) and data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        return None


def load_github(repo: str, client: GitHubClient | None = None) -> RepoContext:
    client = client or GitHubClient()
    meta = client.get(f"/repos/{repo}")
    files: list[WorkflowFile] = []
    try:
        listing = client.get(f"/repos/{repo}/contents/.github/workflows")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise
        listing = []
    for item in listing if isinstance(listing, list) else []:
        name = item.get("name", "")
        if item.get("type") == "file" and name.endswith((".yml", ".yaml")):
            text = client.file_text(repo, item["path"]) or ""
            files.append(parse_workflow(item["path"], text))
    dep = False
    for name in (".github/dependabot.yml", ".github/dependabot.yaml"):
        t = client.file_text(repo, name)
        if t:
            dep = dep or _dependabot_covers_actions(t)
    ren = any(client.file_text(repo, f) for f in RENOVATE_FILES)
    return RepoContext(
        name=repo,
        workflows=files,
        has_dependabot_actions=dep,
        has_renovate=ren,
        is_public=not meta.get("private", False),
    )
