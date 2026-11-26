"""Local report history store using SQLite (stdlib only).

Supports:
- Adding reports (v1, v2, v3): perdedor history add <report>
- Querying and filtering: perdedor history list --profile X
- Output formats: text, JSON, and Markdown
"""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .exposure import assess
from .report_reader import read_report


def default_store_path() -> Path:
    env = os.environ.get("PERDEDOR_HISTORY")
    if env:
        return Path(env)
    # Check repository root or current directory
    repo_root = Path(__file__).resolve().parents[3]
    candidate = repo_root / ".perdedor" / "history.sqlite"
    try:
        candidate.parent.mkdir(parents=True, exist_ok=True)
        return candidate
    except OSError:
        pass
    # Fallback to user home
    home_dir = Path.home() / ".perdedor"
    try:
        home_dir.mkdir(parents=True, exist_ok=True)
        return home_dir / "history.sqlite"
    except OSError:
        return Path(".perdedor_history.sqlite")


class HistoryStore:
    def __init__(self, db_path: str | Path | None = None):
        self.path = Path(db_path) if db_path else default_store_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS reports (
                    scan_id TEXT PRIMARY KEY,
                    schema_version INTEGER,
                    platform TEXT NOT NULL,
                    profile TEXT,
                    hostname TEXT,
                    generated_at TEXT,
                    score REAL,
                    verdict TEXT,
                    clean INTEGER,
                    detected INTEGER,
                    errored INTEGER,
                    skipped INTEGER,
                    total INTEGER,
                    environment_name TEXT,
                    environment_os TEXT,
                    image_id TEXT,
                    hypervisor TEXT,
                    seed INTEGER,
                    report_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_profile ON reports (profile);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_platform ON reports (platform);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_generated ON reports (generated_at);")
            conn.commit()

    def add(self, report_input: str | Path | dict) -> dict:
        """Add a report to the history store and return its summary record."""
        report = read_report(report_input, validate=False)
        scan_id = report["scan_id"]
        platform = report.get("platform", "unknown")
        selection = report.get("selection") or {}
        profile = selection.get("profile", "standard")
        hostname = report.get("hostname", "unknown")
        generated_at = report.get("generated_at", "")
        seed = report.get("seed")

        summary = report.get("summary") or {}
        clean = summary.get("clean", 0)
        detected = summary.get("detected", 0)
        errored = summary.get("errored", 0)
        skipped = summary.get("skipped", 0)
        total = summary.get("total", clean + detected + errored + skipped)

        # Calculate exposure score and verdict if possible
        score = None
        verdict = "unknown"
        try:
            a = assess(report.get("findings", []), platform)
            if a.get("score") is not None:
                score = round(float(a["score"]), 1)
                verdict = str(a.get("verdict", "unknown"))
        except Exception:
            if "weighted_score" in summary:
                score = round(float(summary["weighted_score"]), 1)
                verdict = "pass" if score >= 90 else "warn" if score >= 70 else "fail"

        env = report.get("environment") or {}
        env_name = env.get("name", "")
        env_os = env.get("os", platform)
        image_id = env.get("image_id", "")
        hypervisor = env.get("hypervisor", "")

        created_at = datetime.now(timezone.utc).isoformat()
        report_json = json.dumps(report)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO reports (
                    scan_id, schema_version, platform, profile, hostname, generated_at,
                    score, verdict, clean, detected, errored, skipped, total,
                    environment_name, environment_os, image_id, hypervisor, seed,
                    report_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    report.get("schema_version", 3),
                    platform,
                    profile,
                    hostname,
                    generated_at,
                    score,
                    verdict,
                    clean,
                    detected,
                    errored,
                    skipped,
                    total,
                    env_name,
                    env_os,
                    image_id,
                    hypervisor,
                    seed,
                    report_json,
                    created_at,
                ),
            )
            conn.commit()

        return {
            "scan_id": scan_id,
            "platform": platform,
            "profile": profile,
            "hostname": hostname,
            "generated_at": generated_at,
            "score": score,
            "verdict": verdict,
            "detected": detected,
            "total": total,
            "environment_name": env_name,
        }

    def list(
        self,
        *,
        profile: str | None = None,
        platform: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """List reports in reverse chronological order with optional filtering."""
        query = (
            "SELECT scan_id, schema_version, platform, profile, hostname, generated_at, "
            "score, verdict, clean, detected, errored, skipped, total, "
            "environment_name, environment_os, image_id, hypervisor, seed, created_at "
            "FROM reports WHERE 1=1"
        )
        params: list[Any] = []
        if profile:
            query += " AND profile = ?"
            params.append(profile)
        if platform:
            query += " AND platform = ?"
            params.append(platform)

        query += " ORDER BY generated_at DESC, created_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get(self, identifier: str) -> dict | None:
        """Fetch report by exact scan_id, scan_id prefix, or profile name (latest)."""
        with self._get_connection() as conn:
            # 1. Exact scan_id match
            row = conn.execute(
                "SELECT report_json FROM reports WHERE scan_id = ?", (identifier,)
            ).fetchone()
            if row:
                return json.loads(row["report_json"])

            # 2. Prefix match
            row = conn.execute(
                "SELECT report_json FROM reports WHERE scan_id LIKE ? ORDER BY generated_at DESC LIMIT 1",
                (f"{identifier}%",),
            ).fetchone()
            if row:
                return json.loads(row["report_json"])

            # 3. Latest by profile
            row = conn.execute(
                "SELECT report_json FROM reports WHERE profile = ? ORDER BY generated_at DESC, created_at DESC LIMIT 1",
                (identifier,),
            ).fetchone()
            if row:
                return json.loads(row["report_json"])

        return None


def render_history_text(rows: list[dict]) -> str:
    if not rows:
        return "No reports found in history."
    header = f"{'SCAN ID':<36}  {'DATE (UTC)':<19}  {'PLATFORM':<8}  {'PROFILE':<8}  {'SCORE':<6}  {'VERDICT':<7}  {'DET/TOT':<8}  {'ENVIRONMENT'}"
    lines = [header, "-" * len(header)]
    for r in rows:
        score_str = f"{r['score']:.1f}" if r["score"] is not None else "n/a"
        verdict_str = (r.get("verdict") or "unknown").upper()
        det_str = f"{r['detected']}/{r['total']}"
        date_str = (r.get("generated_at") or "")[:19].replace("T", " ")
        env_str = r.get("environment_name") or "-"
        lines.append(
            f"{r['scan_id']:<36}  {date_str:<19}  {r['platform']:<8}  {r.get('profile') or '-':<8}  "
            f"{score_str:<6}  {verdict_str:<7}  {det_str:<8}  {env_str}"
        )
    return "\n".join(lines)


def render_history_markdown(rows: list[dict]) -> str:
    if not rows:
        return "_No reports found in history._"
    lines = [
        "| Scan ID | Date (UTC) | Platform | Profile | Score | Verdict | Detected / Total | Environment |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        score_str = f"{r['score']:.1f}" if r["score"] is not None else "n/a"
        verdict_str = (r.get("verdict") or "unknown").upper()
        det_str = f"{r['detected']}/{r['total']}"
        date_str = (r.get("generated_at") or "")[:19].replace("T", " ")
        env_str = r.get("environment_name") or "-"
        lines.append(
            f"| `{r['scan_id']}` | {date_str} | {r['platform']} | {r.get('profile') or '-'} | "
            f"{score_str} | {verdict_str} | {det_str} | {env_str} |"
        )
    return "\n".join(lines)
