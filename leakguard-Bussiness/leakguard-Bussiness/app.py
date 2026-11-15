"""
LeakGuard Business - Intelligent Security Monitoring & Incident Management
BTech Second-Year Academic Project Prototype

Backend: Python Flask
Database: Supabase (PostgreSQL) with SQLite fallback
Frontend: HTML5/CSS3/JavaScript (vanilla), Chart.js

Designed for local development AND Vercel deployment.
Faculty-ready: includes one-click demo simulation mode.
"""

import os
import sys
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, g

# Try to load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # .env loading is optional; environment variables can be set manually

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "leakguard-academic-demo-key-2025")

# Supabase configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")  # service_role key for backend
SUPABASE_DB_URL = os.getenv("SUPABASE_DB_URL")  # Direct PostgreSQL connection string

USE_SUPABASE = bool(SUPABASE_URL and SUPABASE_KEY)


def get_supabase_client():
    """Get Supabase client for read/write operations."""
    if not USE_SUPABASE:
        return None
    try:
        from supabase import create_client
        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except ImportError:
        return None


def get_db_connection():
    """
    Get a database connection.
    Uses Supabase PostgreSQL if configured, otherwise falls back to SQLite.
    """
    if SUPABASE_DB_URL:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(SUPABASE_DB_URL)
        conn.autocommit = False
        return conn
    else:
        import sqlite3
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leakguard.db")
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn


def init_db():
    """Initialize database tables. Works with both Supabase PostgreSQL and SQLite."""
    conn = get_db_connection()
    cur = conn.cursor()

    is_postgres = SUPABASE_DB_URL is not None

    if is_postgres:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                role VARCHAR(100) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) NOT NULL,
                event_type VARCHAR(100) NOT NULL,
                timestamp TIMESTAMP DEFAULT NOW(),
                source_ip VARCHAR(100),
                details TEXT
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id SERIAL PRIMARY KEY,
                incident_id VARCHAR(255) UNIQUE NOT NULL,
                title VARCHAR(500) NOT NULL,
                username VARCHAR(255) NOT NULL,
                severity VARCHAR(50) NOT NULL DEFAULT 'High',
                status VARCHAR(50) NOT NULL DEFAULT 'Open',
                detection_timestamp TIMESTAMP DEFAULT NOW(),
                evidence TEXT,
                event_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incident_status_history (
                id SERIAL PRIMARY KEY,
                incident_id VARCHAR(255) NOT NULL,
                old_status VARCHAR(50),
                new_status VARCHAR(50) NOT NULL,
                changed_at TIMESTAMP DEFAULT NOW(),
                changed_by VARCHAR(100) DEFAULT 'admin'
            );
        """)
    else:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                event_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                details TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                severity TEXT NOT NULL DEFAULT 'High',
                status TEXT NOT NULL DEFAULT 'Open',
                detection_timestamp TEXT NOT NULL,
                evidence TEXT,
                event_count INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incident_status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                changed_by TEXT DEFAULT 'admin'
            )
        """)

    # Insert default users if not present (SQLite only)
    if not is_postgres:
        default_users = [
            ("demo_user", "employee"),
            ("john_doe", "employee"),
            ("admin_sim", "administrator"),
            ("test_account", "contractor"),
        ]
        for username, role in default_users:
            try:
                cur.execute(
                    "INSERT INTO users (username, role, created_at) VALUES (?, ?, ?)",
                    (username, role, datetime.now().isoformat()),
                )
            except Exception:
                pass  # User already exists

    conn.commit()
    cur.close()
    conn.close()
    print("Database tables initialized.")


def _now_iso():
    return datetime.now().isoformat()


def _now_dt():
    return datetime.now()


def row_to_dict(cur, row):
    """Convert a DB row to a dict."""
    if row is None:
        return None
    columns = [desc[0] for desc in cur.description]
    return dict(zip(columns, row))


def _serialize_ts(value):
    """Convert a timestamp to ISO string."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def run_detection_engine(conn=None):
    """
    Rule-based threat detection.
    Rule: 5+ failed logins within 60 seconds for same username → High severity incident.
    Avoids duplicate active incidents for the same pattern.
    """
    close_after = False
    if conn is None:
        conn = get_db_connection()
        close_after = True

    cur = conn.cursor()
    is_postgres = SUPABASE_DB_URL is not None

    if is_postgres:
        window_start = _now_dt() - timedelta(seconds=60)
        cur.execute("""
            SELECT username, COUNT(*) as fail_count
            FROM security_events
            WHERE event_type = %s
              AND timestamp >= %s
            GROUP BY username
            HAVING COUNT(*) >= 5
        """, ("login_failed", window_start))
    else:
        window_start = (_now_dt() - timedelta(seconds=60)).isoformat()
        cur.execute("""
            SELECT username, COUNT(*) as fail_count
            FROM security_events
            WHERE event_type = ?
              AND timestamp >= ?
            GROUP BY username
            HAVING fail_count >= 5
        """, ("login_failed", window_start))

    suspicious = cur.fetchall()
    incidents_created = 0

    for row in suspicious:
        username = row[0]
        fail_count = row[1]

        # Check for existing active incident to avoid duplicates
        if is_postgres:
            cur.execute("""
                SELECT id FROM incidents
                WHERE username = %s
                  AND status IN (%s, %s)
                  AND title LIKE %s
            """, (username, "Open", "Investigating",
                  f"%Suspicious login activity - {username}%"))
        else:
            cur.execute("""
                SELECT id FROM incidents
                WHERE username = ?
                  AND status IN ('Open', 'Investigating')
                  AND title LIKE ?
            """, (username, f"%Suspicious login activity - {username}%"))

        if cur.fetchone():
            continue  # Skip duplicate

        # Gather evidence timestamps
        if is_postgres:
            cur.execute("""
                SELECT timestamp FROM security_events
                WHERE username = %s AND event_type = %s
                ORDER BY timestamp DESC LIMIT 10
            """, (username, "login_failed"))
        else:
            cur.execute("""
                SELECT timestamp FROM security_events
                WHERE username = ? AND event_type = 'login_failed'
                ORDER BY timestamp DESC LIMIT 10
            """, (username,))

        failed_rows = cur.fetchall()
        timestamps = [_serialize_ts(r[0]) for r in failed_rows]

        evidence = (
            f"Detected {fail_count} failed login attempts for username '{username}' "
            f"within a 60-second window. This pattern is consistent with brute-force "
            f"or credential-stuffing activity. Recent failed attempt timestamps: "
            f"{', '.join(timestamps)}."
        )

        incident_id = f"INC-{_now_dt().strftime('%Y%m%d%H%M%S')}-{username.upper()}"
        now = _now_dt()
        now_iso = now.isoformat()

        if is_postgres:
            cur.execute("""
                INSERT INTO incidents
                (incident_id, title, username, severity, status, detection_timestamp,
                 evidence, event_count, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                incident_id,
                f"Suspicious login activity - {username}",
                username,
                "High",
                "Open",
                now,
                evidence,
                fail_count,
                now,
                now,
            ))
            cur.execute("""
                INSERT INTO incident_status_history
                (incident_id, old_status, new_status, changed_at, changed_by)
                VALUES (%s, %s, %s, %s, %s)
            """, (incident_id, None, "Open", now, "system"))
        else:
            cur.execute("""
                INSERT INTO incidents
                (incident_id, title, username, severity, status, detection_timestamp,
                 evidence, event_count, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                f"Suspicious login activity - {username}",
                username,
                "High",
                "Open",
                now_iso,
                evidence,
                fail_count,
                now_iso,
                now_iso,
            ))
            cur.execute("""
                INSERT INTO incident_status_history
                (incident_id, old_status, new_status, changed_at, changed_by)
                VALUES (?, ?, ?, ?, ?)
            """, (incident_id, None, "Open", now_iso, "system"))

        incidents_created += 1

    conn.commit()

    if close_after:
        cur.close()
        conn.close()

    return incidents_created


# ============================================================================
# ROUTES
# ============================================================================

@app.route("/")
def dashboard():
    """Serve the main dashboard page."""
    return render_template("dashboard.html")


@app.route("/api/health")
def api_health():
    """Health check endpoint."""
    db_type = "supabase-postgres" if SUPABASE_DB_URL else ("supabase-rest" if USE_SUPABASE else "sqlite")
    return jsonify({
        "status": "healthy",
        "service": "LeakGuard Business",
        "database": db_type,
        "timestamp": _now_iso()
    })


@app.route("/api/stats")
def api_stats():
    """Return dashboard statistics."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = SUPABASE_DB_URL is not None

        def q(sql, params=()):
            cur.execute(sql, params)
            return cur.fetchone()[0]

        if is_postgres:
            total_events = q("SELECT COUNT(*) FROM security_events")
            total_incidents = q("SELECT COUNT(*) FROM incidents")
            open_incidents = q("SELECT COUNT(*) FROM incidents WHERE status = %s", ("Open",))
            investigating = q("SELECT COUNT(*) FROM incidents WHERE status = %s", ("Investigating",))
            closed = q("SELECT COUNT(*) FROM incidents WHERE status = %s", ("Closed",))
            high = q("SELECT COUNT(*) FROM incidents WHERE severity = %s", ("High",))
        else:
            total_events = q("SELECT COUNT(*) FROM security_events")
            total_incidents = q("SELECT COUNT(*) FROM incidents")
            open_incidents = q("SELECT COUNT(*) FROM incidents WHERE status = 'Open'")
            investigating = q("SELECT COUNT(*) FROM incidents WHERE status = 'Investigating'")
            closed = q("SELECT COUNT(*) FROM incidents WHERE status = 'Closed'")
            high = q("SELECT COUNT(*) FROM incidents WHERE severity = 'High'")

        cur.close()
        conn.close()

        return jsonify({
            "total_events": total_events,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "investigating_incidents": investigating,
            "closed_incidents": closed,
            "high_severity": high,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/events")
def api_events():
    """Return recent security events."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = SUPABASE_DB_URL is not None

        cur.execute("""
            SELECT id, username, event_type, timestamp, source_ip, details
            FROM security_events ORDER BY timestamp DESC LIMIT 20
        """)

        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        events = [dict(zip(columns, row)) for row in rows]

        for ev in events:
            if ev.get("timestamp"):
                ev["timestamp"] = _serialize_ts(ev["timestamp"])

        cur.close()
        conn.close()
        return jsonify(events)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents")
def api_incidents():
    """Return all incidents."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = SUPABASE_DB_URL is not None

        cur.execute("""
            SELECT incident_id, title, username, severity, status,
                   detection_timestamp, evidence, event_count, created_at, updated_at
            FROM incidents ORDER BY detection_timestamp DESC
        """)

        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description]
        incidents = [dict(zip(columns, row)) for row in rows]

        for inc in incidents:
            for key in ("detection_timestamp", "created_at", "updated_at"):
                if inc.get(key):
                    inc[key] = _serialize_ts(inc[key])

        cur.close()
        conn.close()
        return jsonify(incidents)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/simulate_login", methods=["POST"])
def api_simulate_login():
    """
    Simulate a login attempt.
    Body: { "username": "demo_user", "result": "failed" }
    """
    try:
        data = request.get_json(silent=True) or {}
        username = data.get("username", "demo_user").strip() or "demo_user"
        result = data.get("result", "failed")

        if result not in ("success", "failed"):
            return jsonify({"error": "result must be 'success' or 'failed'"}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = SUPABASE_DB_URL is not None
        now = _now_dt()
        now_iso = now.isoformat()

        # Ensure user exists
        if is_postgres:
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO users (username, role, created_at) VALUES (%s, %s, %s)",
                    (username, "employee", now),
                )

            cur.execute("""
                INSERT INTO security_events (username, event_type, timestamp, source_ip, details)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                username,
                "login_success" if result == "success" else "login_failed",
                now,
                request.remote_addr or "127.0.0.1",
                f"Simulated {result} login for user {username}",
            ))
        else:
            cur.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO users (username, role, created_at) VALUES (?, ?, ?)",
                    (username, "employee", now_iso),
                )
            cur.execute("""
                INSERT INTO security_events (username, event_type, timestamp, source_ip, details)
                VALUES (?, ?, ?, ?, ?)
            """, (
                username,
                "login_success" if result == "success" else "login_failed",
                now_iso,
                request.remote_addr or "127.0.0.1",
                f"Simulated {result} login for user {username}",
            ))

        conn.commit()

        incidents_created = 0
        if result == "failed":
            incidents_created = run_detection_engine(conn)

        cur.close()
        conn.close()

        return jsonify({
            "status": "recorded",
            "username": username,
            "event_type": f"login_{result}",
            "timestamp": now_iso,
            "incidents_created": incidents_created,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/demo_simulate", methods=["POST"])
def api_demo_simulate():
    """
    Faculty demo mode: runs the complete attack scenario in one call.
    Simulates 5 rapid failed logins for demo_user, triggering the detection engine.
    Body: { "username": "demo_user", "count": 5 }
    """
    try:
        data = request.get_json(silent=True) or {}
        username = data.get("username", "demo_user").strip() or "demo_user"
        count = int(data.get("count", 5))

        if count < 1 or count > 50:
            return jsonify({"error": "count must be between 1 and 50"}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = SUPABASE_DB_URL is not None
        now = _now_dt()
        now_iso = now.isoformat()

        # Ensure user exists
        if is_postgres:
            cur.execute("SELECT id FROM users WHERE username = %s", (username,))
            if cur.fetchone() is None:
                cur.execute(
                    "INSERT INTO users (username, role, created_at) VALUES (%s, %s, %s)",
                    (username, "employee", now),
                )

        # Insert N failed login events rapidly (same second to trigger detection)
        for i in range(count):
            event_time = now  # Same timestamp so all within 60-second window
            if is_postgres:
                cur.execute("""
                    INSERT INTO security_events (username, event_type, timestamp, source_ip, details)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    username, "login_failed", event_time,
                    "192.168.1.100",
                    f"Demo simulated failed login #{i+1} for user {username}",
                ))
            else:
                cur.execute("""
                    INSERT INTO security_events (username, event_type, timestamp, source_ip, details)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    username, "login_failed", now_iso,
                    "192.168.1.100",
                    f"Demo simulated failed login #{i+1} for user {username}",
                ))

        conn.commit()

        # Run detection engine
        incidents_created = run_detection_engine(conn)

        cur.close()
        conn.close()

        return jsonify({
            "status": "demo_complete",
            "username": username,
            "failed_logins_simulated": count,
            "incidents_created": incidents_created,
            "message": f"Simulated {count} failed logins. Detection engine created {incidents_created} incident(s).",
            "timestamp": now_iso
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Reset all demo data for a fresh faculty demonstration."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM incident_status_history")
        cur.execute("DELETE FROM incidents")
        cur.execute("DELETE FROM security_events")
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({
            "status": "reset_complete",
            "message": "Demo data cleared. Ready for fresh demonstration."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/run_detection", methods=["POST"])
def api_run_detection():
    """Manually trigger the detection engine."""
    try:
        count = run_detection_engine()
        return jsonify({
            "status": "detection_complete",
            "potential_incidents": count
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/<incident_id>/status", methods=["PATCH"])
def api_update_incident_status(incident_id):
    """Update the status of an incident."""
    try:
        data = request.get_json(silent=True) or {}
        new_status = data.get("status")

        valid_statuses = ["Open", "Investigating", "Closed", "Resolved", "False positive"]
        if new_status not in valid_statuses:
            return jsonify({
                "error": f"Invalid status. Must be one of: {valid_statuses}"
            }), 400

        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = SUPABASE_DB_URL is not None
        now = _now_dt()
        now_iso = now.isoformat()

        if is_postgres:
            cur.execute("SELECT status FROM incidents WHERE incident_id = %s", (incident_id,))
            row = cur.fetchone()
            if row is None:
                cur.close()
                conn.close()
                return jsonify({"error": "Incident not found"}), 404

            old_status = row[0]
            cur.execute("""
                UPDATE incidents SET status = %s, updated_at = %s WHERE incident_id = %s
            """, (new_status, now, incident_id))
            cur.execute("""
                INSERT INTO incident_status_history
                (incident_id, old_status, new_status, changed_at, changed_by)
                VALUES (%s, %s, %s, %s, %s)
            """, (incident_id, old_status, new_status, now, "admin"))
        else:
            cur.execute("SELECT status FROM incidents WHERE incident_id = ?", (incident_id,))
            row = cur.fetchone()
            if row is None:
                cur.close()
                conn.close()
                return jsonify({"error": "Incident not found"}), 404

            old_status = row[0]
            cur.execute("""
                UPDATE incidents SET status = ?, updated_at = ? WHERE incident_id = ?
            """, (new_status, now_iso, incident_id))
            cur.execute("""
                INSERT INTO incident_status_history
                (incident_id, old_status, new_status, changed_at, changed_by)
                VALUES (?, ?, ?, ?, ?)
            """, (incident_id, old_status, new_status, now_iso, "admin"))

        conn.commit()
        cur.close()
        conn.close()

        return jsonify({
            "status": "updated",
            "incident_id": incident_id,
            "old_status": old_status,
            "new_status": new_status,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/incidents/<incident_id>")
def api_incident_detail(incident_id):
    """Return details of a single incident including status history."""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        is_postgres = SUPABASE_DB_URL is not None

        if is_postgres:
            cur.execute("""
                SELECT incident_id, title, username, severity, status,
                       detection_timestamp, evidence, event_count, created_at, updated_at
                FROM incidents WHERE incident_id = %s
            """, (incident_id,))
        else:
            cur.execute("""
                SELECT incident_id, title, username, severity, status,
                       detection_timestamp, evidence, event_count, created_at, updated_at
                FROM incidents WHERE incident_id = ?
            """, (incident_id,))

        row = cur.fetchone()
        if row is None:
            cur.close()
            conn.close()
            return jsonify({"error": "Incident not found"}), 404

        columns = [desc[0] for desc in cur.description]
        incident = dict(zip(columns, row))

        # History
        if is_postgres:
            cur.execute("""
                SELECT old_status, new_status, changed_at, changed_by
                FROM incident_status_history WHERE incident_id = %s
                ORDER BY changed_at ASC
            """, (incident_id,))
        else:
            cur.execute("""
                SELECT old_status, new_status, changed_at, changed_by
                FROM incident_status_history WHERE incident_id = ?
                ORDER BY changed_at ASC
            """, (incident_id,))

        hist_rows = cur.fetchall()
        h_columns = [desc[0] for desc in cur.description]
        history = [dict(zip(h_columns, r)) for r in hist_rows]
        for h in history:
            if h.get("changed_at"):
                h["changed_at"] = _serialize_ts(h["changed_at"])

        incident["status_history"] = history

        for key in ("detection_timestamp", "created_at", "updated_at"):
            if incident.get(key):
                incident[key] = _serialize_ts(incident[key])

        cur.close()
        conn.close()
        return jsonify(incident)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ============================================================================
# APP INITIALIZATION
# ============================================================================

if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("LeakGuard Business - Security Monitoring & Incident Management")
    print("BTech Second-Year Academic Project Prototype")
    print("Database:", "Supabase PostgreSQL" if SUPABASE_DB_URL else ("Supabase REST" if USE_SUPABASE else "SQLite (local)"))
    print("=" * 60)
    port = int(os.getenv("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
