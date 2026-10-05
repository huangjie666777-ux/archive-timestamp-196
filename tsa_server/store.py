"""SQLite-backed receipt store with atomic serial allocation.

Serial numbers are allocated inside a BEGIN IMMEDIATE transaction, so
concurrent issuers can never draw the same number. A receipt row is
only committed together with its signed token; a signing failure rolls
the transaction back and leaves no successful record. Rows from a
crash between allocation and commit (receipt IS NULL) are purged on
startup and are never served.
"""

from __future__ import annotations

import datetime as dt
import sqlite3
import threading
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    serial   INTEGER PRIMARY KEY AUTOINCREMENT,
    gen_time TEXT,
    receipt  BLOB
);
"""


class ClockMovedBackwards(Exception):
    pass


def _ts(when: dt.datetime) -> str:
    return when.astimezone(dt.timezone.utc).strftime("%Y%m%d%H%M%SZ")


class Store:
    def __init__(self, db_path: Path):
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.execute("DELETE FROM receipts WHERE receipt IS NULL")
        self._conn.commit()

    def issue(self, sign) -> tuple[int, dt.datetime, bytes]:
        """Allocate a serial, call sign(serial, gen_time) -> bytes, commit."""
        with self._lock:
            now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
            cur = self._conn.cursor()
            cur.execute("BEGIN IMMEDIATE")
            try:
                cur.execute(
                    "INSERT INTO receipts (gen_time, receipt) VALUES (NULL, NULL)"
                )
                serial = cur.lastrowid
                row = cur.execute(
                    "SELECT MAX(gen_time) FROM receipts WHERE receipt IS NOT NULL"
                ).fetchone()
                if row and row[0] and _ts(now) < row[0]:
                    raise ClockMovedBackwards(
                        f"clock { _ts(now) } is behind last issued {row[0]}"
                    )
                receipt = sign(serial, now)
                cur.execute(
                    "UPDATE receipts SET gen_time = ?, receipt = ? WHERE serial = ?",
                    (_ts(now), receipt, serial),
                )
                self._conn.commit()
                return serial, now, receipt
            except BaseException:
                self._conn.rollback()
                raise

    def get(self, serial: int) -> bytes | None:
        row = self._conn.execute(
            "SELECT receipt FROM receipts WHERE serial = ? AND receipt IS NOT NULL",
            (serial,),
        ).fetchone()
        return row[0] if row else None

    def count(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM receipts WHERE receipt IS NOT NULL"
        ).fetchone()[0]

    def close(self) -> None:
        self._conn.close()

