#!/usr/bin/env python3
"""Merge duplicate server rows before applying the hostname-uniqueness
migration (582d74304304).

If you registered the same hostname more than once before this fix
(e.g. by re-running a setup script, or losing an API key and
re-registering to get a new one), your `servers` table has more than
one row for the same machine — and `alembic upgrade head` will fail
with `UNIQUE constraint failed: servers.hostname` until you run this.

This script does NOT discard scan history. For each duplicate
hostname group, it:
  1. Picks a survivor (the row with the most scans; ties broken by
     most recently created).
  2. Reassigns every scan and finding from the other rows onto the
     survivor's id.
  3. Deletes the now-empty duplicate rows.

Safe to run multiple times (a no-op if there are no duplicates).
Always back up your database file first if it matters to you:

    cp dashboard/data/sentinelguard.db dashboard/data/sentinelguard.db.bak

Usage:
    python3 cleanup_duplicate_servers.py [path-to-sentinelguard.db]

If no path is given, defaults to dashboard/data/sentinelguard.db
relative to the current directory.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


def main() -> None:
    db_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("dashboard/data/sentinelguard.db")
    if not db_path.exists():
        print(f"ERROR: database file not found at {db_path}")
        print("Pass the path explicitly: python3 cleanup_duplicate_servers.py <path>")
        sys.exit(1)

    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")

    duplicate_hostnames = conn.execute(
        """
        SELECT hostname, COUNT(*) as cnt
        FROM servers
        GROUP BY hostname
        HAVING cnt > 1
        """
    ).fetchall()

    if not duplicate_hostnames:
        print("No duplicate hostnames found. Nothing to do.")
        print("You can safely run: cd dashboard && alembic upgrade head")
        return

    total_merged = 0
    for hostname, count in duplicate_hostnames:
        print(f"\nHostname '{hostname}' has {count} server rows:")

        rows = conn.execute(
            """
            SELECT s.id, s.created_at, COUNT(sc.id) as scan_count
            FROM servers s
            LEFT JOIN scans sc ON sc.server_id = s.id
            WHERE s.hostname = ?
            GROUP BY s.id
            ORDER BY scan_count DESC, s.created_at DESC
            """,
            (hostname,),
        ).fetchall()

        survivor_id = rows[0][0]
        loser_ids = [r[0] for r in rows[1:]]

        for server_id, created_at, scan_count in rows:
            marker = "KEEP (survivor)" if server_id == survivor_id else "merge into survivor"
            print(f"  - {server_id}  scans={scan_count}  created={created_at}  [{marker}]")

        for loser_id in loser_ids:
            scans_moved = conn.execute(
                "UPDATE scans SET server_id = ? WHERE server_id = ?",
                (survivor_id, loser_id),
            ).rowcount
            findings_moved = conn.execute(
                "UPDATE findings SET server_id = ? WHERE server_id = ?",
                (survivor_id, loser_id),
            ).rowcount
            conn.execute("DELETE FROM servers WHERE id = ?", (loser_id,))
            print(
                f"  Merged {loser_id}: moved {scans_moved} scan(s), "
                f"{findings_moved} finding(s) -> {survivor_id}, then removed the duplicate row."
            )
            total_merged += 1

    conn.commit()
    conn.close()

    print(f"\nDone. Merged {total_merged} duplicate server row(s) across "
          f"{len(duplicate_hostnames)} hostname(s).")
    print("You can now safely run: cd dashboard && alembic upgrade head")


if __name__ == "__main__":
    main()
