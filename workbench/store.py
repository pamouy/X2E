"""Storage: SQLite (self-hosted, one file) or Postgres (serverless, DATABASE_URL).

Everything that belongs to a project is stored encrypted (see vault.py), so both backends hold ciphertext.
SQL is written once, in SQLite style with '?' placeholders; the Postgres backend translates it.
"""
from __future__ import annotations

import os
import sqlite3
import threading

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value BLOB);
CREATE TABLE IF NOT EXISTS projects(id TEXT PRIMARY KEY, created TEXT NOT NULL, wrapped_key BLOB NOT NULL, enc_meta BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS connectors(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, platform TEXT NOT NULL, role TEXT NOT NULL,
    created TEXT NOT NULL, enc_config BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, connector_id TEXT NOT NULL, created TEXT NOT NULL,
    size INTEGER NOT NULL, enc_name BLOB NOT NULL, enc_data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS runs(id TEXT PRIMARY KEY, project_id TEXT NOT NULL, connector_id TEXT NOT NULL, platform TEXT NOT NULL,
    role TEXT NOT NULL, status TEXT NOT NULL, started TEXT NOT NULL, finished TEXT, enc_manifest BLOB, enc_log BLOB,
    step TEXT NOT NULL DEFAULT '', steps_done INTEGER NOT NULL DEFAULT 0, cancel INTEGER NOT NULL DEFAULT 0, heartbeat TEXT);
CREATE TABLE IF NOT EXISTS blobs(run_id TEXT NOT NULL, name TEXT NOT NULL, project_id TEXT NOT NULL, enc_data BLOB NOT NULL, PRIMARY KEY(run_id, name));
CREATE TABLE IF NOT EXISTS analyses(connector_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, run_id TEXT NOT NULL, target_run_id TEXT,
    created TEXT NOT NULL, enc_data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS kv(project_id TEXT NOT NULL, key TEXT NOT NULL, enc_value BLOB NOT NULL, PRIMARY KEY(project_id, key));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, project_id TEXT, action TEXT NOT NULL, detail TEXT);
CREATE INDEX IF NOT EXISTS runs_by_connector ON runs(connector_id, started);
"""
PROJECT_TABLES = ("connectors", "files", "runs", "blobs", "analyses", "kv")
RUN_COLUMNS = (("step", "TEXT NOT NULL DEFAULT ''"), ("steps_done", "INTEGER NOT NULL DEFAULT 0"), ("cancel", "INTEGER NOT NULL DEFAULT 0"), ("heartbeat", "TEXT"))


class StoreError(Exception):
    pass


class _Base:
    backend = ""

    def meta_get(self, key: str) -> bytes | None:
        row = self.one("SELECT value FROM meta WHERE key=?", (key,))
        return bytes(row["value"]) if row and row["value"] is not None else None

    def meta_set(self, key: str, value: bytes) -> None:
        self.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def delete_project(self, project_id: str) -> None:
        stmts = [(f"DELETE FROM {t} WHERE project_id=?", (project_id,)) for t in PROJECT_TABLES]
        stmts.append(("DELETE FROM projects WHERE id=?", (project_id,)))
        self.transaction(stmts)
        self.after_delete()

    def after_delete(self) -> None:
        pass


class SqliteStore(_Base):
    backend = "sqlite"

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.path = path
        self._lock = threading.RLock()
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=30)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA secure_delete=ON")
        self._db.executescript(SCHEMA)
        have = {r["name"] for r in self._db.execute("PRAGMA table_info(runs)")}
        for name, ddl in RUN_COLUMNS:                      # databases created by version 0.1
            if name not in have:
                self._db.execute(f"ALTER TABLE runs ADD COLUMN {name} {ddl}")
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def execute(self, sql: str, params: tuple = ()) -> int:
        with self._lock:
            return self._db.execute(sql, params).rowcount

    def all(self, sql: str, params: tuple = ()) -> list:
        with self._lock:
            return self._db.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple = ()):
        with self._lock:
            return self._db.execute(sql, params).fetchone()

    def transaction(self, statements: list[tuple[str, tuple]]) -> None:
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                for sql, params in statements:
                    self._db.execute(sql, params)
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def after_delete(self) -> None:
        with self._lock:
            self._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def close(self) -> None:
        with self._lock:
            self._db.close()


class PostgresStore(_Base):
    """One connection per process, re-opened when the server drops it. Statements are not prepared,
    so a pooled connection string (PgBouncer, Neon pooler) works."""
    backend = "postgres"

    def __init__(self, dsn: str):
        import psycopg
        from psycopg.rows import dict_row
        self._psycopg, self._row = psycopg, dict_row
        self._dsn = dsn
        self._lock = threading.RLock()
        self._db = None
        self._connect()
        ddl = SCHEMA.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "BIGSERIAL PRIMARY KEY").replace("BLOB", "BYTEA")
        with self._lock:
            for stmt in (s.strip() for s in ddl.split(";")):
                if stmt:
                    self._db.execute(stmt)
            for name, col in RUN_COLUMNS:
                self._db.execute(f"ALTER TABLE runs ADD COLUMN IF NOT EXISTS {name} {col}")

    def _connect(self) -> None:
        try:
            self._db = self._psycopg.connect(self._dsn, autocommit=True, row_factory=self._row, prepare_threshold=None, connect_timeout=15)
        except self._psycopg.Error as exc:
            raise StoreError(f"Cannot connect to the database: {type(exc).__name__}") from exc

    @staticmethod
    def _sql(sql: str) -> str:
        return sql.replace("%", "%%").replace("?", "%s")

    def _run(self, fn):
        with self._lock:
            try:
                return fn()
            except (self._psycopg.OperationalError, self._psycopg.InterfaceError):
                self._connect()                       # the server or the pooler closed an idle connection
                return fn()

    def execute(self, sql: str, params: tuple = ()) -> int:
        return self._run(lambda: self._db.execute(self._sql(sql), params).rowcount)

    def all(self, sql: str, params: tuple = ()) -> list:
        return self._run(lambda: self._db.execute(self._sql(sql), params).fetchall())

    def one(self, sql: str, params: tuple = ()):
        return self._run(lambda: self._db.execute(self._sql(sql), params).fetchone())

    def transaction(self, statements: list[tuple[str, tuple]]) -> None:
        def work():
            with self._db.transaction():
                for sql, params in statements:
                    self._db.execute(self._sql(sql), params)
        self._run(work)

    def close(self) -> None:
        with self._lock:
            self._db.close()


def open_store(data_dir: str | None = None):
    """Postgres when DATABASE_URL (or POSTGRES_URL) is set, otherwise a SQLite file in the data directory."""
    dsn = os.environ.get("WORKBENCH_DATABASE_URL") or os.environ.get("DATABASE_URL") or os.environ.get("POSTGRES_URL")
    if dsn:
        return PostgresStore(dsn)
    if os.environ.get("VERCEL"):
        raise StoreError("No database configured. Add a Postgres database to the Vercel project (Storage tab) so that DATABASE_URL is set, then redeploy.")
    return SqliteStore(os.path.join(data_dir or os.environ.get("WORKBENCH_DATA", "./data"), "workbench.db"))


Store = SqliteStore          # name kept for code written against version 0.1
