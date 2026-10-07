import sqlite3
import json
import threading
from typing import List, Dict, Any, Optional
from netguard.alerts.models import Alert
from netguard.flow.tracker import Flow


class AlertStore:
    """
    SQLite persistence layer for security alerts, network flow summaries,
    and rolling minute statistics.
    """
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._shared_conn: Optional[sqlite3.Connection] = None

        if self.db_path == ":memory:":
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row

        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        if self._shared_conn is not None:
            return self._shared_conn

        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _close_connection(self, conn: sqlite3.Connection) -> None:
        if conn is not self._shared_conn:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id TEXT PRIMARY KEY,
                        ts REAL NOT NULL,
                        alert_type TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        src TEXT,
                        dst TEXT,
                        description TEXT NOT NULL,
                        evidence_json TEXT
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);")

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS flows_summary (
                        flow_key TEXT NOT NULL,
                        proto TEXT NOT NULL,
                        src TEXT,
                        dst TEXT,
                        sport INTEGER,
                        dport INTEGER,
                        start_ts REAL NOT NULL,
                        last_seen_ts REAL NOT NULL,
                        total_packets INTEGER NOT NULL,
                        total_bytes INTEGER NOT NULL,
                        tcp_state TEXT
                    );
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_src ON flows_summary(src);")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_last_seen ON flows_summary(last_seen_ts);")

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS stats_minute (
                        minute_ts REAL PRIMARY KEY,
                        total_packets INTEGER NOT NULL,
                        total_bytes INTEGER NOT NULL,
                        alerts_count INTEGER NOT NULL,
                        tcp_count INTEGER NOT NULL,
                        udp_count INTEGER NOT NULL,
                        arp_count INTEGER NOT NULL,
                        other_count INTEGER NOT NULL
                    );
                """)
                conn.commit()
            finally:
                self._close_connection(conn)

    def save_alert(self, alert: Alert) -> None:
        self.save_alerts([alert])

    def save_alerts(self, alerts: List[Alert]) -> None:
        if not alerts:
            return
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                records = [
                    (
                        a.id,
                        a.ts,
                        a.alert_type,
                        a.severity,
                        a.src,
                        a.dst,
                        a.description,
                        json.dumps(a.evidence)
                    )
                    for a in alerts
                ]
                cursor.executemany("""
                    INSERT OR REPLACE INTO alerts (id, ts, alert_type, severity, src, dst, description, evidence_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, records)
                conn.commit()
            finally:
                self._close_connection(conn)

    def get_alerts(
        self,
        alert_type: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[float] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                query = "SELECT id, ts, alert_type, severity, src, dst, description, evidence_json FROM alerts WHERE 1=1"
                params: List[Any] = []

                if alert_type:
                    query += " AND alert_type = ?"
                    params.append(alert_type)
                if severity:
                    query += " AND severity = ?"
                    params.append(severity)
                if since is not None:
                    query += " AND ts >= ?"
                    params.append(since)

                query += " ORDER BY ts DESC LIMIT ?"
                params.append(limit)

                cursor.execute(query, params)
                rows = cursor.fetchall()

                results = []
                for row in rows:
                    evidence = {}
                    if row["evidence_json"]:
                        try:
                            evidence = json.loads(row["evidence_json"])
                        except Exception:
                            pass
                    results.append({
                        "id": row["id"],
                        "ts": row["ts"],
                        "alert_type": row["alert_type"],
                        "severity": row["severity"],
                        "src": row["src"],
                        "dst": row["dst"],
                        "description": row["description"],
                        "evidence": evidence
                    })
                return results
            finally:
                self._close_connection(conn)

    def save_flow(self, flow: Flow) -> None:
        self.save_flows([flow])

    def save_flows(self, flows: List[Flow]) -> None:
        if not flows:
            return
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                records = [
                    (
                        str(f.key),
                        f.proto,
                        f.initiator_ip,
                        f.responder_ip,
                        f.initiator_port,
                        f.responder_port,
                        f.start_ts,
                        f.last_seen_ts,
                        f.total_packets,
                        f.total_bytes,
                        f.tcp_state
                    )
                    for f in flows
                ]
                cursor.executemany("""
                    INSERT INTO flows_summary (
                        flow_key, proto, src, dst, sport, dport, start_ts, last_seen_ts, total_packets, total_bytes, tcp_state
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, records)
                conn.commit()
            finally:
                self._close_connection(conn)

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Calculates top source hosts by cumulative bytes transmitted.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT src as ip, SUM(total_bytes) as bytes_sent, SUM(total_packets) as packets_sent
                    FROM flows_summary
                    WHERE src IS NOT NULL
                    GROUP BY src
                    ORDER BY bytes_sent DESC
                    LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                return [{"ip": r["ip"], "bytes": r["bytes_sent"], "packets": r["packets_sent"]} for r in rows]
            finally:
                self._close_connection(conn)

    def get_protocol_distribution(self) -> Dict[str, int]:
        """
        Calculates protocol breakdown by packet counts from stored flows.
        """
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT proto, SUM(total_packets) as count
                    FROM flows_summary
                    GROUP BY proto
                """)
                rows = cursor.fetchall()
                return {r["proto"]: r["count"] for r in rows}
            finally:
                self._close_connection(conn)

    def record_minute_stats(
        self,
        minute_ts: float,
        total_packets: int,
        total_bytes: int,
        alerts_count: int,
        breakdown: Dict[str, int]
    ) -> None:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO stats_minute (
                        minute_ts, total_packets, total_bytes, alerts_count, tcp_count, udp_count, arp_count, other_count
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    minute_ts,
                    total_packets,
                    total_bytes,
                    alerts_count,
                    breakdown.get("TCP", 0),
                    breakdown.get("UDP", 0),
                    breakdown.get("ARP", 0),
                    breakdown.get("OTHER", 0)
                ))
                conn.commit()
            finally:
                self._close_connection(conn)

    def get_minute_stats(self, limit: int = 60) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT * FROM stats_minute ORDER BY minute_ts DESC LIMIT ?
                """, (limit,))
                rows = cursor.fetchall()
                return [dict(r) for r in rows]
            finally:
                self._close_connection(conn)

    def close(self) -> None:
        with self._lock:
            if self._shared_conn is not None:
                self._shared_conn.close()
                self._shared_conn = None
