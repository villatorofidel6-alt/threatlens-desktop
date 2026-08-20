"""Local SQLite history. Reports stay on the user's machine."""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

from threatlens.models import AnalysisReport


def app_data_dir() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    location = base / "ThreatLens"
    location.mkdir(parents=True, exist_ok=True)
    return location


class HistoryStore:
    """A small local-only report index with search by target or hash."""

    def __init__(self, database_path: Path | None = None) -> None:
        self.database_path = database_path or app_data_dir() / "history.sqlite3"
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    analyzed_at TEXT NOT NULL,
                    sha256 TEXT,
                    risk_score INTEGER NOT NULL,
                    report_json TEXT NOT NULL
                )
                """
            )
            connection.execute("CREATE INDEX IF NOT EXISTS idx_analyses_target ON analyses(target)")
            connection.execute("CREATE INDEX IF NOT EXISTS idx_analyses_sha256 ON analyses(sha256)")

    def save(self, report: AnalysisReport) -> int:
        payload = json.dumps(report.to_dict(), ensure_ascii=False)
        sha256 = report.metadata.get("hashes", {}).get("sha256") if report.target_type == "file" else None
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO analyses(target, target_type, analyzed_at, sha256, risk_score, report_json)
                VALUES(?, ?, ?, ?, ?, ?)
                """,
                (report.target, report.target_type, report.analyzed_at, sha256, report.risk_score, payload),
            )
            return int(cursor.lastrowid)

    def search(self, query: str = "", limit: int = 100) -> list[dict[str, object]]:
        pattern = f"%{query.strip()}%"
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, target, target_type, analyzed_at, sha256, risk_score, report_json
                FROM analyses
                WHERE target LIKE ? OR COALESCE(sha256, '') LIKE ?
                ORDER BY id DESC LIMIT ?
                """,
                (pattern, pattern, limit),
            ).fetchall()
        return [
            {
                "id": row["id"],
                "target": row["target"],
                "target_type": row["target_type"],
                "analyzed_at": row["analyzed_at"],
                "sha256": row["sha256"],
                "risk_score": row["risk_score"],
                "report": json.loads(row["report_json"]),
            }
            for row in rows
        ]
