"""Known GitHub Actions supply-chain incidents, for `ghaudit exposure`.

Every entry comes from a public advisory (see `reference`). Times are UTC. When an advisory gives dates
but no times, the window covers the whole days, and the advisory's own "check logs between" guidance is
used where it is wider. Add new incidents here; tests check that every entry is well formed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def utc(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class Incident:
    id: str
    name: str
    actions: tuple[str, ...]                 # owner/repo of every affected action
    windows: tuple[tuple[datetime, datetime], ...]
    malicious_shas: tuple[str, ...] = ()
    affected_refs: str = "all tags"          # plain-English description
    safe: str = ""                           # first safe version, or how to get one
    stole: str = ""
    reference: str = ""
    iocs: tuple[str, ...] = field(default_factory=tuple)
    pin_protects: bool = True                # False when the action fetched the compromised code itself


INCIDENTS: tuple[Incident, ...] = (
    Incident(
        id="CVE-2025-30154", name="reviewdog/action-setup@v1 compromise",
        actions=("reviewdog/action-setup", "reviewdog/action-shellcheck", "reviewdog/action-composite-template",
                 "reviewdog/action-staticcheck", "reviewdog/action-ast-grep", "reviewdog/action-typos"),
        windows=((utc("2025-03-11T18:42:00"), utc("2025-03-11T20:31:00")),),
        malicious_shas=("f0d342d24037bb11d26b9bd8496e0808ba32e9ec",),
        affected_refs="action-setup@v1, and the listed reviewdog actions that call it, whatever their pin",
        safe="any run outside the window; pin to a reviewed SHA",
        stole="CI/CD secrets printed into workflow logs",
        reference="https://github.com/advisories/GHSA-qmg3-hpqr-gqvc",
        pin_protects=False,
    ),
    Incident(
        id="CVE-2025-30066", name="tj-actions/changed-files tag hijack",
        actions=("tj-actions/changed-files",),
        windows=((utc("2025-03-14T00:00:00"), utc("2025-03-15T23:59:59")),),
        malicious_shas=("0e58ed8671d6b60d0890c21b07f8835ace038e67",),
        affected_refs="every version up to 45.0.7: all tags pointed to the malicious commit",
        safe="46.0.1",
        stole="CI/CD secrets printed into workflow logs (readable by anyone for public repositories)",
        reference="https://github.com/advisories/GHSA-mrrh-fwg8-r2c3",
    ),
    Incident(
        id="CVE-2026-33634", name="aquasecurity/trivy-action and setup-trivy tag hijack (TeamPCP)",
        actions=("aquasecurity/trivy-action", "aquasecurity/setup-trivy"),
        windows=((utc("2026-03-19T00:00:00"), utc("2026-03-20T23:59:59")),),
        affected_refs="trivy-action 0.0.1-0.34.2 (76 of 77 tags force-pushed); setup-trivy 0.2.0-0.2.6",
        safe="trivy-action 0.35.0; setup-trivy 0.2.6 (recreated); Trivy binary 0.69.2 or 0.69.3, never 0.69.4",
        stole="credential-stealing malware on the runner: CI tokens, cloud, SSH and database credentials",
        reference="https://cve.circl.lu/cve/CVE-2026-33634",
        iocs=("a repository named tpcp-docs in your organisation", "Trivy v0.69.4 in logs or images"),
    ),
    Incident(
        id="CHECKMARX-2026-03", name="Checkmarx GitHub Actions compromise (TeamPCP)",
        actions=("checkmarx/ast-github-action", "checkmarx/kics-github-action"),
        windows=((utc("2026-03-23T12:58:00"), utc("2026-03-23T19:16:00")),
                 (utc("2026-04-22T14:17:59"), utc("2026-04-22T15:41:31"))),
        malicious_shas=("f1d2a3477e0d8e42a4e7ad15b6fc376cf910e373", "f58de2470825e8ee7c0b3ecc194a948056381003",
                        "aa52a82cddf2fa5ad54a519a0a56fd430264dbbe"),
        affected_refs="all tags of both actions (second wave on ast-github-action 2.3.35)",
        safe="ast-github-action v2.3.33; kics-github-action v2.1.20",
        stole="environment variables and secrets via a setup.sh on the runner, sent to checkmarx.zone",
        reference="https://isc.sans.edu/diary/32834",
        iocs=("repositories tpcp-docs or docs-tpcp", "connections to checkmarx.zone or *.checkmarx.cx", "files tpcp.tar.gz or setup.sh in runner logs"),
    ),
)

# Workflow files planted by the Shai-Hulud npm worms (September and November 2025).
WORM_FILES = (
    ("shai-hulud-workflow.yml", None, "Shai-Hulud (Sept 2025): workflow that sends secrets to webhook.site"),
    ("discussion.yaml", "github.event.discussion.body", "Sha1-Hulud 2.0 (Nov 2025): backdoor that runs discussion text on a self-hosted runner named SHA1HULUD"),
    ("formatter_", "toJSON(secrets)", "Sha1-Hulud 2.0 (Nov 2025): workflow that dumps every secret into an artifact"),
)
