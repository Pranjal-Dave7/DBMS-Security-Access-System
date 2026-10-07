import sys
import os
import sqlite3
import hashlib
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTableWidget, QTableWidgetItem,
    QStackedWidget, QFrame, QMessageBox, QComboBox, QHeaderView,
    QGridLayout
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont


# ──────────────────────────────────────────────
# DATABASE PATH
# When packaged as exe, database sits next to the exe.
# During development, sits next to main.py.
# ──────────────────────────────────────────────

def get_db_path():
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "security_access.db")


def get_connection():
    conn = sqlite3.connect(get_db_path())
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


# ──────────────────────────────────────────────
# COLOURS & FONTS
# ──────────────────────────────────────────────

BG_MAIN    = "#F5F5F5"
BG_SIDEBAR = "#1E1E2E"
BG_WHITE   = "#FFFFFF"

TEXT_LIGHT = "#FFFFFF"
TEXT_DARK  = "#1A1A2E"
TEXT_MUTED = "#6B7280"

ACCENT  = "#3B82F6"
SUCCESS = "#22C55E"
DANGER  = "#EF4444"
WARNING = "#F59E0B"
INFO    = "#6366F1"

SIDEBAR_ITEM_ACTIVE = "#3B82F6"
FONT_FAMILY = "Segoe UI"


def sha256(text):
    return hashlib.sha256(text.encode()).hexdigest()


def badge_color(status):
    s = str(status).upper()
    if s in ("GRANTED", "ACTIVE", "RECOVERED", "YES"):
        return SUCCESS
    if s in ("DENIED", "BLOCKED", "FLAGGED", "LOST", "SUSPENDED", "NO"):
        return DANGER
    if s in ("MEDIUM", "HIGH"):
        return WARNING
    if s == "CRITICAL":
        return DANGER
    return TEXT_MUTED


def make_font(size=13, bold=False):
    f = QFont(FONT_FAMILY, size)
    f.setBold(bold)
    return f


# ──────────────────────────────────────────────
# DATABASE INITIALISATION
# Creates all tables, triggers, and sample data
# if the database file does not exist yet.
# ──────────────────────────────────────────────

def init_db():
    path = get_db_path()
    already_exists = os.path.exists(path)
    conn = get_connection()
    cur  = conn.cursor()

    # ── TABLE 1: ROOMS ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS rooms (
            room_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            room_name      TEXT    NOT NULL,
            room_type      TEXT    NOT NULL DEFAULT 'LAB'
                           CHECK(room_type IN ('LAB','SERVER_ROOM','OFFICE')),
            required_level INTEGER NOT NULL DEFAULT 1
        )
    """)

    # ── TABLE 2: STUDENTS ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS students (
            student_id    TEXT PRIMARY KEY,
            full_name     TEXT    NOT NULL,
            department    TEXT,
            year_of_study INTEGER,
            access_level  INTEGER NOT NULL DEFAULT 1,
            status        TEXT    NOT NULL DEFAULT 'ACTIVE'
                          CHECK(status IN ('ACTIVE','SUSPENDED','BLOCKED'))
        )
    """)

    # ── TABLE 3: ACCESS LOGS ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            log_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id  TEXT,
            room_id     INTEGER,
            swipe_time  TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now','localtime')),
            status      TEXT NOT NULL
                        CHECK(status IN ('GRANTED','DENIED','BLOCKED','FLAGGED')),
            deny_reason TEXT,
            FOREIGN KEY (student_id) REFERENCES students(student_id),
            FOREIGN KEY (room_id)    REFERENCES rooms(room_id)
        )
    """)

    # ── TABLE 4: LOST CARDS ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS lost_cards (
            lost_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id  TEXT NOT NULL,
            reported_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now','localtime')),
            status      TEXT NOT NULL DEFAULT 'LOST'
                        CHECK(status IN ('LOST','RECOVERED')),
            FOREIGN KEY (student_id) REFERENCES students(student_id)
        )
    """)

    # ── TABLE 5: SECURITY ALERTS ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            alert_id     INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id   TEXT,
            alert_type   TEXT NOT NULL
                         CHECK(alert_type IN (
                             'LOST_CARD_USED','REPEATED_FAILURE',
                             'AFTER_HOURS_ATTEMPT','RECONNAISSANCE_PATTERN',
                             'UNAUTHORIZED_LEVEL'
                         )),
            description  TEXT,
            triggered_at TEXT DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now','localtime')),
            is_resolved  INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (student_id) REFERENCES students(student_id)
        )
    """)

    # ── TABLE 6: ADMIN USERS ──
    cur.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            admin_id      INTEGER PRIMARY KEY AUTOINCREMENT,
            username      TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name     TEXT,
            role          TEXT NOT NULL DEFAULT 'SECURITY_OFFICER'
                          CHECK(role IN ('SUPERADMIN','SECURITY_OFFICER'))
        )
    """)

    # ── TRIGGER 1: Auto-block after 3 failures in 30 minutes ──
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_auto_block_on_failures
        AFTER INSERT ON access_logs
        WHEN NEW.status IN ('DENIED','BLOCKED','FLAGGED')
        BEGIN
            UPDATE students
            SET    status = 'BLOCKED'
            WHERE  student_id = NEW.student_id
              AND (
                SELECT COUNT(*) FROM access_logs
                WHERE  student_id = NEW.student_id
                  AND  status IN ('DENIED','BLOCKED','FLAGGED')
                  AND  swipe_time >= datetime('now','localtime','-30 minutes')
              ) >= 3;

            INSERT INTO security_alerts (student_id, alert_type, description)
            SELECT NEW.student_id, 'REPEATED_FAILURE',
                   'Student automatically blocked after 3 failed attempts in 30 minutes'
            WHERE (
                SELECT COUNT(*) FROM access_logs
                WHERE  student_id = NEW.student_id
                  AND  status IN ('DENIED','BLOCKED','FLAGGED')
                  AND  swipe_time >= datetime('now','localtime','-30 minutes')
            ) >= 3
            AND NOT EXISTS (
                SELECT 1 FROM security_alerts
                WHERE  student_id = NEW.student_id
                  AND  alert_type = 'REPEATED_FAILURE'
                  AND  is_resolved = 0
                  AND  triggered_at >= datetime('now','localtime','-30 minutes')
            );
        END
    """)

    # ── TRIGGER 2: Reconnaissance pattern detection ──
    cur.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_recon_detection
        AFTER INSERT ON access_logs
        WHEN NEW.status = 'GRANTED'
        BEGIN
            INSERT INTO security_alerts (student_id, alert_type, description)
            SELECT NEW.student_id, 'RECONNAISSANCE_PATTERN',
                   'Student entered ' ||
                   (SELECT COUNT(DISTINCT room_id) FROM access_logs
                    WHERE student_id = NEW.student_id
                      AND status = 'GRANTED'
                      AND swipe_time >= datetime('now','localtime','-5 minutes'))
                   || ' different rooms in under 5 minutes - possible reconnaissance'
            WHERE (
                SELECT COUNT(DISTINCT room_id) FROM access_logs
                WHERE  student_id = NEW.student_id
                  AND  status = 'GRANTED'
                  AND  swipe_time >= datetime('now','localtime','-5 minutes')
            ) >= 3
            AND NOT EXISTS (
                SELECT 1 FROM security_alerts
                WHERE  student_id = NEW.student_id
                  AND  alert_type = 'RECONNAISSANCE_PATTERN'
                  AND  is_resolved = 0
                  AND  triggered_at >= datetime('now','localtime','-5 minutes')
            );
        END
    """)

    conn.commit()

    # Insert sample data only if DB was just created
    if not already_exists:
        _insert_sample_data(cur)
        conn.commit()

    conn.close()


def _insert_sample_data(cur):

    # Rooms
    cur.executemany(
        "INSERT INTO rooms (room_name, room_type, required_level) VALUES (?,?,?)",
        [
            ('Computer Lab A',  'LAB',         1),
            ('Computer Lab B',  'LAB',         1),
            ('Electronics Lab', 'LAB',         1),
            ('Research Lab',    'LAB',         3),
            ('Server Room',     'SERVER_ROOM', 5),
            ('HOD Office',      'OFFICE',      4),
        ]
    )

    # Students
    cur.executemany(
        "INSERT INTO students (student_id,full_name,department,year_of_study,access_level,status) VALUES (?,?,?,?,?,?)",
        [
            ('STU-001', 'Arjun Mehta',     'Computer Science', 2, 1, 'ACTIVE'),
            ('STU-002', 'Priya Shah',      'Electronics',      3, 1, 'ACTIVE'),
            ('STU-003', 'Rohan Patel',     'Computer Science', 4, 2, 'ACTIVE'),
            ('STU-004', 'Sneha Joshi',     'Information Tech', 1, 1, 'SUSPENDED'),
            ('STU-005', 'Karan Desai',     'Computer Science', 3, 3, 'ACTIVE'),
            ('STU-006', 'Anjali Verma',    'Electronics',      2, 1, 'ACTIVE'),
            ('STU-007', 'Dev Sharma',      'Computer Science', 5, 5, 'ACTIVE'),
            ('STU-008', 'Vikram Singh',    'Electronics',      3, 1, 'BLOCKED'),
            ('STU-009', 'Meera Nair',      'Information Tech', 2, 1, 'ACTIVE'),
            ('STU-010', 'Rahul Gupta',     'Computer Science', 1, 1, 'ACTIVE'),
            ('STU-011', 'Tanvi Rao',       'Electronics',      4, 2, 'ACTIVE'),
            ('STU-012', 'Sahil Khan',      'Computer Science', 3, 1, 'BLOCKED'),
            ('STU-013', 'Pooja Iyer',      'Information Tech', 2, 1, 'ACTIVE'),
            ('STU-014', 'Aditya Bose',     'Computer Science', 1, 1, 'ACTIVE'),
            ('STU-015', 'Riya Menon',      'Electronics',      3, 1, 'ACTIVE'),
            ('STU-016', 'Nikhil Jain',     'Computer Science', 4, 2, 'ACTIVE'),
            ('STU-017', 'Simran Kaur',     'Information Tech', 2, 1, 'SUSPENDED'),
            ('STU-018', 'Harsh Malhotra',  'Computer Science', 3, 1, 'ACTIVE'),
            ('STU-019', 'Divya Reddy',     'Electronics',      1, 1, 'ACTIVE'),
            ('STU-020', 'Amit Trivedi',    'Computer Science', 2, 1, 'ACTIVE'),
            ('STU-021', 'Kavya Pillai',    'Information Tech', 3, 1, 'ACTIVE'),
            ('STU-022', 'Siddharth Rao',   'Computer Science', 4, 3, 'ACTIVE'),
            ('STU-023', 'Ishaan Chandra',  'Electronics',      2, 1, 'BLOCKED'),
            ('STU-024', 'Nandini Saxena',  'Computer Science', 1, 1, 'ACTIVE'),
            ('STU-025', 'Yash Kulkarni',   'Information Tech', 3, 2, 'ACTIVE'),
            ('STU-026', 'Trisha Ghosh',    'Electronics',      4, 1, 'ACTIVE'),
            ('STU-027', 'Manav Oberoi',    'Computer Science', 2, 1, 'ACTIVE'),
            ('STU-028', 'Shruti Pandey',   'Information Tech', 1, 1, 'ACTIVE'),
            ('STU-029', 'Akash Singhania', 'Computer Science', 3, 1, 'SUSPENDED'),
            ('STU-030', 'Lavanya Nambiar', 'Electronics',      2, 1, 'ACTIVE'),
        ]
    )

    # Admin users
    cur.executemany(
        "INSERT INTO admin_users (username,password_hash,full_name,role) VALUES (?,?,?,?)",
        [
            ('admin',      sha256('admin123'), 'System Administrator', 'SUPERADMIN'),
            ('security01', sha256('sec@2024'), 'Ramesh Kumar',         'SECURITY_OFFICER'),
        ]
    )

    # Lost cards
    cur.execute("INSERT INTO lost_cards (student_id, status) VALUES ('STU-006','LOST')")
    cur.execute("INSERT INTO lost_cards (student_id, status) VALUES ('STU-009','RECOVERED')")

    # Access logs — 35 entries using datetime offsets
    logs = [
        ('STU-001', 1,  -1,    'GRANTED', None),
        ('STU-001', 2,  -2,    'GRANTED', None),
        ('STU-002', 3,  -3,    'GRANTED', None),
        ('STU-005', 4,  -4,    'GRANTED', None),
        ('STU-007', 5,  -5,    'GRANTED', None),
        ('STU-003', 1,  -6,    'GRANTED', None),
        ('STU-011', 3,  -7,    'GRANTED', None),
        ('STU-010', 2,  -8,    'GRANTED', None),
        ('STU-009', 1,  -9,    'GRANTED', None),
        ('STU-005', 1,  -10,   'GRANTED', None),
        ('STU-007', 4,  -11,   'GRANTED', None),
        ('STU-001', 1,  -24,   'GRANTED', None),
        ('STU-002', 1,  -25,   'GRANTED', None),
        ('STU-003', 2,  -48,   'GRANTED', None),
        ('STU-010', 1,  -49,   'GRANTED', None),
        ('STU-001', 5,  -12,   'DENIED',  'Student has access level 1 but this room requires level 5'),
        ('STU-002', 5,  -13,   'DENIED',  'Student has access level 1 but this room requires level 5'),
        ('STU-003', 5,  -14,   'DENIED',  'Student has access level 2 but this room requires level 5'),
        ('STU-010', 6,  -15,   'DENIED',  'Student has access level 1 but this room requires level 4'),
        ('STU-011', 4,  -16,   'DENIED',  'Student has access level 2 but this room requires level 3'),
        ('STU-009', 5,  -72,   'DENIED',  'Student has access level 1 but this room requires level 5'),
        ('STU-004', 1,  -17,   'BLOCKED', 'Student account is blocked or suspended'),
        ('STU-008', 1,  -18,   'BLOCKED', 'Student account is blocked or suspended'),
        ('STU-012', 2,  -19,   'BLOCKED', 'Student account is blocked or suspended'),
        ('STU-004', 2,  -48,   'BLOCKED', 'Student account is blocked or suspended'),
        ('STU-008', 3,  -72,   'BLOCKED', 'Student account is blocked or suspended'),
        ('STU-006', 1,  -20,   'FLAGGED', 'Card reported as lost - possible unauthorized use'),
        ('STU-006', 2,  -21,   'FLAGGED', 'Card reported as lost - possible unauthorized use'),
        ('STU-001', 1,  -22,   'DENIED',  'Access not allowed between 11 PM and 6 AM'),
        ('STU-002', 3,  -23,   'DENIED',  'Access not allowed between 11 PM and 6 AM'),
        ('STU-005', 1,  -96,   'DENIED',  'Access not allowed between 11 PM and 6 AM'),
        ('STU-001', 1,  0,     'GRANTED', None),
        ('STU-007', 5,  0,     'GRANTED', None),
        ('STU-003', 4,  -1,    'DENIED',  'Student has access level 2 but this room requires level 3'),
        ('STU-010', 5,  -1,    'DENIED',  'Student has access level 1 but this room requires level 5'),
    ]
    for sid, rid, hour_offset, status, reason in logs:
        t = f"datetime('now','localtime','{hour_offset} hours')"
        cur.execute(
            f"INSERT INTO access_logs (student_id,room_id,swipe_time,status,deny_reason) "
            f"VALUES (?,?,{t},?,?)",
            (sid, rid, status, reason)
        )

    # Security alerts
    alerts = [
        ('STU-006', 'LOST_CARD_USED',         'A card marked as lost was used to attempt room entry',                            -20, 0),
        ('STU-006', 'LOST_CARD_USED',         'A card marked as lost was used to attempt room entry',                            -21, 0),
        ('STU-001', 'UNAUTHORIZED_LEVEL',     'Student with level 1 attempted to enter a room that requires level 5',            -12, 0),
        ('STU-003', 'UNAUTHORIZED_LEVEL',     'Student with level 2 attempted to enter a room that requires level 5',            -14, 0),
        ('STU-008', 'REPEATED_FAILURE',       'Student automatically blocked after 3 failed attempts in 30 minutes',             -72, 1),
        ('STU-012', 'REPEATED_FAILURE',       'Student automatically blocked after 3 failed attempts in 30 minutes',             -19, 0),
        ('STU-001', 'AFTER_HOURS_ATTEMPT',    'Student attempted to enter a room during restricted hours (11 PM to 6 AM)',       -22, 1),
        ('STU-005', 'RECONNAISSANCE_PATTERN', 'Student entered 3 different rooms in under 5 minutes - possible reconnaissance',  -96, 1),
    ]
    for sid, atype, desc, hour_offset, resolved in alerts:
        t = f"datetime('now','localtime','{hour_offset} hours')"
        cur.execute(
            f"INSERT INTO security_alerts (student_id,alert_type,description,triggered_at,is_resolved) "
            f"VALUES (?,?,?,{t},?)",
            (sid, atype, desc, resolved)
        )


# ──────────────────────────────────────────────
# PROCESS SWIPE — application layer logic
# (equivalent to the MySQL stored procedure)
# Checks in order:
#   1. Student exists?
#   2. Card reported lost?
#   3. Student blocked/suspended?
#   4. After hours? (11 PM – 6 AM)
#   5. Access level sufficient?
#   6. All passed → GRANTED
# ──────────────────────────────────────────────

def process_swipe(student_id, room_id):
    conn = get_connection()
    cur  = conn.cursor()

    # Check 1: Does the student exist?
    cur.execute(
        "SELECT access_level, status FROM students WHERE student_id=?",
        (student_id,)
    )
    student = cur.fetchone()
    if not student:
        cur.execute(
            "INSERT INTO access_logs (student_id,room_id,status,deny_reason) VALUES (?,?,?,?)",
            (student_id, room_id, 'DENIED', 'Student ID not found in system')
        )
        conn.commit(); conn.close()
        return 'DENIED', 'Student ID not found in system'

    access_level   = student['access_level']
    student_status = student['status']

    # Check 2: Is the card reported lost?
    cur.execute(
        "SELECT COUNT(*) as cnt FROM lost_cards WHERE student_id=? AND status='LOST'",
        (student_id,)
    )
    if cur.fetchone()['cnt'] > 0:
        cur.execute(
            "INSERT INTO access_logs (student_id,room_id,status,deny_reason) VALUES (?,?,?,?)",
            (student_id, room_id, 'FLAGGED', 'Card reported as lost - possible unauthorized use')
        )
        cur.execute(
            "INSERT INTO security_alerts (student_id,alert_type,description) VALUES (?,?,?)",
            (student_id, 'LOST_CARD_USED', 'A card marked as lost was used to attempt room entry')
        )
        conn.commit(); conn.close()
        return 'FLAGGED', 'Card reported as lost - possible unauthorized use'

    # Check 3: Is the student blocked or suspended?
    if student_status in ('BLOCKED', 'SUSPENDED'):
        cur.execute(
            "INSERT INTO access_logs (student_id,room_id,status,deny_reason) VALUES (?,?,?,?)",
            (student_id, room_id, 'BLOCKED', 'Student account is blocked or suspended')
        )
        conn.commit(); conn.close()
        return 'BLOCKED', 'Student account is blocked or suspended'

    # Check 4: After hours? (11 PM = 23, before 6 AM = 0–5)
    current_hour = datetime.now().hour
    if current_hour >= 23 or current_hour < 6:
        cur.execute(
            "INSERT INTO access_logs (student_id,room_id,status,deny_reason) VALUES (?,?,?,?)",
            (student_id, room_id, 'DENIED', 'Access not allowed between 11 PM and 6 AM')
        )
        cur.execute(
            "INSERT INTO security_alerts (student_id,alert_type,description) VALUES (?,?,?)",
            (student_id, 'AFTER_HOURS_ATTEMPT',
             'Student attempted to enter a room during restricted hours (11 PM to 6 AM)')
        )
        conn.commit(); conn.close()
        return 'DENIED', 'Access not allowed between 11 PM and 6 AM'

    # Check 5: Does the student have enough access level?
    cur.execute(
        "SELECT required_level, room_name FROM rooms WHERE room_id=?",
        (room_id,)
    )
    room = cur.fetchone()
    if not room:
        conn.close()
        return 'DENIED', 'Room not found'

    required_level = room['required_level']
    room_name      = room['room_name']

    if access_level < required_level:
        reason = (f"Student has access level {access_level} "
                  f"but this room requires level {required_level}")
        cur.execute(
            "INSERT INTO access_logs (student_id,room_id,status,deny_reason) VALUES (?,?,?,?)",
            (student_id, room_id, 'DENIED', reason)
        )
        cur.execute(
            "INSERT INTO security_alerts (student_id,alert_type,description) VALUES (?,?,?)",
            (student_id, 'UNAUTHORIZED_LEVEL',
             f"Student with level {access_level} attempted to enter a room that requires level {required_level}")
        )
        conn.commit(); conn.close()
        return 'DENIED', reason

    # All checks passed — GRANT ACCESS
    cur.execute(
        "INSERT INTO access_logs (student_id,room_id,status,deny_reason) VALUES (?,?,?,?)",
        (student_id, room_id, 'GRANTED', None)
    )
    conn.commit(); conn.close()
    return 'GRANTED', f'Access granted to {room_name}'


# ──────────────────────────────────────────────
# REUSABLE WIDGETS
# ──────────────────────────────────────────────

class StatCard(QFrame):
    def __init__(self, label, value, color=TEXT_DARK):
        super().__init__()
        self.setStyleSheet(f"""
            QFrame {{
                background: {BG_WHITE};
                border-radius: 10px;
                border: 1px solid #E5E7EB;
            }}
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        self.lbl = QLabel(label)
        self.lbl.setFont(make_font(11))
        self.lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.lbl.setStyleSheet(f"color: {TEXT_MUTED}; border: none;")
        self.val = QLabel(str(value))
        self.val.setFont(make_font(26, bold=True))
        self.val.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.val.setStyleSheet(f"color: {color}; border: none;")
        layout.addWidget(self.lbl)
        layout.addWidget(self.val)

    def set_value(self, v):
        self.val.setText(str(v))


class StyledTable(QTableWidget):
    def __init__(self, headers):
        super().__init__()
        self.setColumnCount(len(headers))
        self.setHorizontalHeaderLabels(headers)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setAlternatingRowColors(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setStyleSheet(f"""
            QTableWidget {{
                background: {BG_WHITE};
                border: none;
                border-radius: 8px;
                font-family: {FONT_FAMILY};
                font-size: 13px;
            }}
            QTableWidget::item {{
                padding: 6px 14px;
                color: {TEXT_DARK};
            }}
            QTableWidget::item:selected {{
                background: #EFF6FF;
                color: {TEXT_DARK};
            }}
            QHeaderView::section {{
                background: #F9FAFB;
                color: {TEXT_MUTED};
                font-weight: bold;
                font-size: 12px;
                padding: 8px 14px;
                border: none;
                border-bottom: 1px solid #E5E7EB;
                text-align: left;
            }}
            QTableWidget::item:alternate {{
                background: #FAFAFA;
            }}
        """)

    def set_badge(self, row, col, text):
        lbl = QLabel(f"  {text}  ")
        lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        color = badge_color(text)
        lbl.setStyleSheet(f"""
            background: {color}22;
            color: {color};
            border-radius: 10px;
            font-size: 11px;
            font-weight: bold;
            padding: 2px 8px;
        """)
        self.setCellWidget(row, col, lbl)

    def fill(self, rows, badge_cols=None):
        badge_cols = badge_cols or []
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            self.setRowHeight(r, 38)
            for c, val in enumerate(row):
                if c in badge_cols:
                    self.set_badge(r, c, str(val))
                else:
                    item = QTableWidgetItem(str(val) if val is not None else "—")
                    item.setFont(make_font(12))
                    item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
                    self.setItem(r, c, item)
        # Set uniform fixed widths so every row aligns cleanly
        col_count = self.columnCount()
        # Narrower width for tables with many columns, wider for fewer columns
        if col_count <= 5:
            col_width = 180
        elif col_count == 6:
            col_width = 150
        else:
            col_width = 120
        for i in range(col_count - 1):
            self.setColumnWidth(i, col_width)
        self.horizontalHeader().setStretchLastSection(True)


class StyledButton(QPushButton):
    def __init__(self, text, color=ACCENT, text_color=TEXT_LIGHT, small=False):
        super().__init__(text)
        padding = "6px 14px" if small else "8px 20px"
        size    = 12 if small else 13
        self.setFont(make_font(size))
        self.setCursor(Qt.PointingHandCursor)
        self.setStyleSheet(f"""
            QPushButton {{
                background: {color};
                color: {text_color};
                border-radius: 7px;
                padding: {padding};
                border: none;
                font-weight: bold;
            }}
            QPushButton:hover   {{ background: {color}CC; }}
            QPushButton:pressed {{ background: {color}99; }}
        """)


class StyledInput(QLineEdit):
    def __init__(self, placeholder=""):
        super().__init__()
        self.setPlaceholderText(placeholder)
        self.setFont(make_font(13))
        self.setFixedHeight(36)
        self.setStyleSheet(f"""
            QLineEdit {{
                border: 1px solid #D1D5DB;
                border-radius: 7px;
                padding: 0 12px;
                background: {BG_WHITE};
                color: {TEXT_DARK};
            }}
            QLineEdit:focus {{ border: 1.5px solid {ACCENT}; }}
        """)


class StyledCombo(QComboBox):
    def __init__(self):
        super().__init__()
        self.setFont(make_font(13))
        self.setFixedHeight(36)
        self.setStyleSheet(f"""
            QComboBox {{
                border: 1px solid #D1D5DB;
                border-radius: 7px;
                padding: 0 12px;
                background: {BG_WHITE};
                color: {TEXT_DARK};
            }}
            QComboBox:focus     {{ border: 1.5px solid {ACCENT}; }}
            QComboBox::drop-down {{ border: none; }}
        """)


def section_label(text):
    lbl = QLabel(text)
    lbl.setFont(make_font(11, bold=True))
    lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
    lbl.setStyleSheet(f"color: {TEXT_MUTED};")
    return lbl


def card_frame():
    f = QFrame()
    f.setStyleSheet(f"""
        QFrame {{
            background: {BG_WHITE};
            border-radius: 10px;
            border: 1px solid #E5E7EB;
        }}
    """)
    return f


def tab_btn_style(active):
    bg = ACCENT if active else "#6B7280"
    hv = f"{ACCENT}CC" if active else "#888"
    return f"""
        QPushButton {{
            background: {bg}; color: white;
            border-radius: 7px; padding: 6px 16px;
            border: none; font-weight: bold; font-size: 12px;
        }}
        QPushButton:hover {{ background: {hv}; }}
    """


# ──────────────────────────────────────────────
# LOGIN SCREEN
# ──────────────────────────────────────────────

class LoginScreen(QWidget):
    def __init__(self, on_success):
        super().__init__()
        self.on_success = on_success
        self.setStyleSheet(f"background: {BG_MAIN};")

        outer = QVBoxLayout(self)
        outer.setAlignment(Qt.AlignCenter)

        box = card_frame()
        box.setFixedWidth(380)
        layout = QVBoxLayout(box)
        layout.setContentsMargins(36, 36, 36, 36)
        layout.setSpacing(14)

        title = QLabel("SecureAccess")
        title.setFont(make_font(22, bold=True))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(f"color: {TEXT_DARK}; border: none;")

        sub = QLabel("Admin Portal — Please log in")
        sub.setFont(make_font(12))
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(f"color: {TEXT_MUTED}; border: none;")

        self.user_input = StyledInput("Username")
        self.pass_input = StyledInput("Password")
        self.pass_input.setEchoMode(QLineEdit.Password)

        self.error_lbl = QLabel("")
        self.error_lbl.setFont(make_font(12))
        self.error_lbl.setAlignment(Qt.AlignCenter)
        self.error_lbl.setStyleSheet(f"color: {DANGER}; border: none;")

        login_btn = StyledButton("Log In")
        login_btn.setFixedHeight(42)
        login_btn.clicked.connect(self.do_login)
        self.pass_input.returnPressed.connect(self.do_login)

        layout.addWidget(title)
        layout.addWidget(sub)
        layout.addSpacing(8)
        layout.addWidget(self.user_input)
        layout.addWidget(self.pass_input)
        layout.addWidget(self.error_lbl)
        layout.addWidget(login_btn)

        outer.addWidget(box)

    def do_login(self):
        username = self.user_input.text().strip()
        password = self.pass_input.text().strip()
        if not username or not password:
            self.error_lbl.setText("Please enter username and password.")
            return
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute(
                "SELECT admin_id FROM admin_users WHERE username=? AND password_hash=?",
                (username, sha256(password))
            )
            row = cur.fetchone()
            conn.close()
            if row:
                self.on_success(username)
            else:
                self.error_lbl.setText("Incorrect username or password.")
        except Exception as e:
            self.error_lbl.setText(f"Error: {e}")


# ──────────────────────────────────────────────
# DASHBOARD
# ──────────────────────────────────────────────

class DashboardScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"background: {BG_MAIN};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        layout.addWidget(section_label("Overview"))

        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.sc_students = StatCard("Total Students", "—")
        self.sc_alerts   = StatCard("Active Alerts",  "—", DANGER)
        self.sc_swipes   = StatCard("Swipes Today",   "—", ACCENT)
        self.sc_blocked  = StatCard("Blocked",        "—", WARNING)
        for w in [self.sc_students, self.sc_alerts, self.sc_swipes, self.sc_blocked]:
            stats_row.addWidget(w)
        layout.addLayout(stats_row)

        layout.addWidget(section_label("Recent Activity"))
        self.table = StyledTable(["Student ID", "Student Name", "Room", "Time", "Status"])
        layout.addWidget(self.table)

        self.load_data()

    def load_data(self):
        try:
            conn = get_connection()
            cur  = conn.cursor()

            cur.execute("SELECT COUNT(*) FROM students")
            self.sc_students.set_value(cur.fetchone()[0])

            cur.execute("SELECT COUNT(*) FROM security_alerts WHERE is_resolved=0")
            self.sc_alerts.set_value(cur.fetchone()[0])

            cur.execute("SELECT COUNT(*) FROM access_logs WHERE date(swipe_time)=date('now','localtime')")
            self.sc_swipes.set_value(cur.fetchone()[0])

            cur.execute("SELECT COUNT(*) FROM students WHERE status='BLOCKED'")
            self.sc_blocked.set_value(cur.fetchone()[0])

            cur.execute("""
                SELECT al.student_id, IFNULL(s.full_name,'Unknown'),
                       IFNULL(r.room_name,'Unknown'),
                       strftime('%d %b %H:%M', al.swipe_time),
                       al.status
                FROM access_logs al
                LEFT JOIN students s ON al.student_id=s.student_id
                LEFT JOIN rooms    r ON al.room_id=r.room_id
                ORDER BY al.swipe_time DESC LIMIT 15
            """)
            self.table.fill(cur.fetchall(), badge_cols=[4])
            conn.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


# ──────────────────────────────────────────────
# STUDENTS SCREEN
# ──────────────────────────────────────────────

class StudentsScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.current_student_id = None
        self.setStyleSheet(f"background: {BG_MAIN};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        search_card = card_frame()
        sc_layout = QHBoxLayout(search_card)
        sc_layout.setContentsMargins(16, 14, 16, 14)
        sc_layout.setSpacing(10)
        self.search_input = StyledInput("Enter Student ID  (e.g. STU-001)")
        search_btn = StyledButton("Search")
        search_btn.clicked.connect(self.search_student)
        self.search_input.returnPressed.connect(self.search_student)
        sc_layout.addWidget(self.search_input)
        sc_layout.addWidget(search_btn)
        layout.addWidget(search_card)

        self.profile_card = card_frame()
        self.profile_card.setVisible(False)
        pc = QVBoxLayout(self.profile_card)
        pc.setContentsMargins(18, 16, 18, 16)
        pc.setSpacing(10)

        self.profile_name   = QLabel("")
        self.profile_name.setFont(make_font(16, bold=True))
        self.profile_name.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.profile_name.setStyleSheet(f"color:{TEXT_DARK}; border:none;")

        self.profile_info   = QLabel("")
        self.profile_info.setFont(make_font(12))
        self.profile_info.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.profile_info.setStyleSheet(f"color:{TEXT_MUTED}; border:none;")

        self.profile_status = QLabel("")
        self.profile_status.setFont(make_font(12, bold=True))
        self.profile_status.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.profile_status.setStyleSheet(f"color:{SUCCESS}; border:none;")

        pc.addWidget(self.profile_name)
        pc.addWidget(self.profile_info)
        pc.addWidget(self.profile_status)
        pc.addWidget(section_label("Last 5 Access Attempts"))

        self.log_table = StyledTable(["Room", "Time", "Status", "Reason"])
        self.log_table.setMaximumHeight(220)
        pc.addWidget(self.log_table)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        for text, color, slot in [
            ("Block",             DANGER,  self.block_student),
            ("Unblock",           SUCCESS, self.unblock_student),
            ("Report Card Lost",  WARNING, self.report_lost),
            ("Recover Card",      ACCENT,  self.recover_card),
        ]:
            btn = StyledButton(text, color, small=True)
            btn.clicked.connect(slot)
            btn_row.addWidget(btn)
        btn_row.addStretch()
        pc.addLayout(btn_row)
        layout.addWidget(self.profile_card)
        layout.addStretch()

    def search_student(self):
        sid = self.search_input.text().strip().upper()
        if not sid:
            return
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute(
                "SELECT student_id,full_name,department,year_of_study,access_level,status FROM students WHERE student_id=?",
                (sid,)
            )
            row = cur.fetchone()
            if not row:
                QMessageBox.warning(self, "Not Found", f"No student found with ID: {sid}")
                self.profile_card.setVisible(False)
                conn.close()
                return
            self.current_student_id = row['student_id']
            self.profile_name.setText(row['full_name'])
            self.profile_info.setText(
                f"Dept: {row['department']}   |   Year: {row['year_of_study']}   |   Access Level: {row['access_level']}"
            )
            color = SUCCESS if row['status'] == 'ACTIVE' else DANGER
            self.profile_status.setText(f"Status: {row['status']}")
            self.profile_status.setStyleSheet(f"color:{color}; border:none; font-weight:bold;")

            cur.execute("""
                SELECT IFNULL(r.room_name,'Unknown'),
                       strftime('%d %b %Y %H:%M', al.swipe_time),
                       al.status, IFNULL(al.deny_reason,'—')
                FROM access_logs al
                LEFT JOIN rooms r ON al.room_id=r.room_id
                WHERE al.student_id=?
                ORDER BY al.swipe_time DESC LIMIT 5
            """, (sid,))
            self.log_table.fill(cur.fetchall(), badge_cols=[2])
            conn.close()
            self.profile_card.setVisible(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _update_status(self, new_status, msg):
        if not self.current_student_id:
            return
        try:
            conn = get_connection()
            conn.execute("UPDATE students SET status=? WHERE student_id=?",
                         (new_status, self.current_student_id))
            conn.commit(); conn.close()
            QMessageBox.information(self, "Done", msg)
            self.search_student()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def block_student(self):
        self._update_status('BLOCKED', f"{self.current_student_id} has been blocked.")

    def unblock_student(self):
        self._update_status('ACTIVE', f"{self.current_student_id} has been unblocked.")

    def report_lost(self):
        if not self.current_student_id:
            return
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM lost_cards WHERE student_id=? AND status='LOST'",
                (self.current_student_id,)
            )
            if cur.fetchone()[0] > 0:
                QMessageBox.warning(self, "Already Lost", "Card is already reported as lost.")
                conn.close()
                return
            conn.execute("INSERT INTO lost_cards (student_id) VALUES (?)", (self.current_student_id,))
            conn.commit(); conn.close()
            QMessageBox.information(self, "Done", "Card reported as lost.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def recover_card(self):
        if not self.current_student_id:
            return
        try:
            conn = get_connection()
            conn.execute(
                "UPDATE lost_cards SET status='RECOVERED' WHERE student_id=? AND status='LOST'",
                (self.current_student_id,)
            )
            conn.commit(); conn.close()
            QMessageBox.information(self, "Done", "Card marked as recovered.")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


# ──────────────────────────────────────────────
# LOGS SCREEN
# ──────────────────────────────────────────────

class LogsScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"background: {BG_MAIN};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.btn_all    = StyledButton("All Logs",      ACCENT)
        self.btn_denied = StyledButton("Denied Access", "#6B7280", TEXT_LIGHT)
        self.btn_night  = StyledButton("Late Night",    "#6B7280", TEXT_LIGHT)
        for b in [self.btn_all, self.btn_denied, self.btn_night]:
            b.setFixedHeight(34)
            btn_row.addWidget(b)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.table = StyledTable(["Log ID", "Student ID", "Student Name", "Room", "Time", "Status", "Reason"])
        layout.addWidget(self.table)

        self.btn_all.clicked.connect(lambda: self.load("all"))
        self.btn_denied.clicked.connect(lambda: self.load("denied"))
        self.btn_night.clicked.connect(lambda: self.load("night"))
        self.load("all")

    def load(self, mode):
        for btn, m in [(self.btn_all,"all"),(self.btn_denied,"denied"),(self.btn_night,"night")]:
            btn.setStyleSheet(tab_btn_style(mode == m))

        queries = {
            "all": """
                SELECT al.log_id, al.student_id, IFNULL(s.full_name,'Unknown'),
                       IFNULL(r.room_name,'Unknown'),
                       strftime('%d %b %Y %H:%M', al.swipe_time),
                       al.status, IFNULL(al.deny_reason,'—')
                FROM access_logs al
                LEFT JOIN students s ON al.student_id=s.student_id
                LEFT JOIN rooms    r ON al.room_id=r.room_id
                ORDER BY al.swipe_time DESC LIMIT 100
            """,
            "denied": """
                SELECT al.log_id, al.student_id, IFNULL(s.full_name,'Unknown'),
                       IFNULL(r.room_name,'Unknown'),
                       strftime('%d %b %Y %H:%M', al.swipe_time),
                       al.status, IFNULL(al.deny_reason,'—')
                FROM access_logs al
                LEFT JOIN students s ON al.student_id=s.student_id
                LEFT JOIN rooms    r ON al.room_id=r.room_id
                WHERE al.status IN ('DENIED','BLOCKED','FLAGGED')
                ORDER BY al.swipe_time DESC
            """,
            "night": """
                SELECT al.log_id, al.student_id, IFNULL(s.full_name,'Unknown'),
                       IFNULL(r.room_name,'Unknown'),
                       strftime('%d %b %Y %H:%M', al.swipe_time),
                       al.status, IFNULL(al.deny_reason,'—')
                FROM access_logs al
                LEFT JOIN students s ON al.student_id=s.student_id
                LEFT JOIN rooms    r ON al.room_id=r.room_id
                WHERE CAST(strftime('%H', al.swipe_time) AS INTEGER) >= 23
                   OR CAST(strftime('%H', al.swipe_time) AS INTEGER) < 6
                ORDER BY al.swipe_time DESC
            """
        }
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute(queries[mode])
            self.table.fill(cur.fetchall(), badge_cols=[5])
            conn.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


# ──────────────────────────────────────────────
# ALERTS SCREEN
# ──────────────────────────────────────────────

class AlertsScreen(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet(f"background: {BG_MAIN};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(12)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.btn_all      = StyledButton("Active Alerts",   ACCENT)
        self.btn_black    = StyledButton("Blacklist Hits",  "#6B7280", TEXT_LIGHT)
        self.btn_intruder = StyledButton("Intruder Alerts", "#6B7280", TEXT_LIGHT)
        self.btn_resolved = StyledButton("Resolved",        "#6B7280", TEXT_LIGHT)
        for b in [self.btn_all, self.btn_black, self.btn_intruder, self.btn_resolved]:
            b.setFixedHeight(34)
            btn_row.addWidget(b)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self.table = StyledTable(["Alert ID", "Student ID", "Student Name", "Alert Type", "Description", "Time", "Resolved"])
        layout.addWidget(self.table)

        self.btn_all.clicked.connect(lambda: self.load("all"))
        self.btn_black.clicked.connect(lambda: self.load("black"))
        self.btn_intruder.clicked.connect(lambda: self.load("intruder"))
        self.btn_resolved.clicked.connect(lambda: self.load("resolved"))
        self.load("all")

    def load(self, mode):
        for btn, m in [
            (self.btn_all,"all"),(self.btn_black,"black"),
            (self.btn_intruder,"intruder"),(self.btn_resolved,"resolved")
        ]:
            btn.setStyleSheet(tab_btn_style(mode == m))

        base = """
            SELECT sa.alert_id, sa.student_id, IFNULL(s.full_name,'Unknown'),
                   sa.alert_type, sa.description,
                   strftime('%d %b %Y %H:%M', sa.triggered_at),
                   CASE sa.is_resolved WHEN 1 THEN 'Yes' ELSE 'No' END
            FROM security_alerts sa
            LEFT JOIN students s ON sa.student_id=s.student_id
        """
        where = {
            "all":      "WHERE sa.is_resolved=0",
            "black":    "WHERE sa.is_resolved=0 AND sa.alert_type IN ('LOST_CARD_USED','REPEATED_FAILURE')",
            "intruder": "WHERE sa.is_resolved=0 AND sa.alert_type IN ('RECONNAISSANCE_PATTERN','UNAUTHORIZED_LEVEL','AFTER_HOURS_ATTEMPT')",
            "resolved": "WHERE sa.is_resolved=1",
        }
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute(base + where[mode] + " ORDER BY sa.triggered_at DESC")
            self.table.fill(cur.fetchall(), badge_cols=[6])
            conn.close()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))


# ──────────────────────────────────────────────
# SIMULATOR SCREEN
# ──────────────────────────────────────────────

class SimulatorScreen(QWidget):
    def __init__(self, alerts_screen=None):
        super().__init__()
        self.alerts_screen = alerts_screen
        self.setStyleSheet(f"background: {BG_MAIN};")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        swipe_card = card_frame()
        sc = QVBoxLayout(swipe_card)
        sc.setContentsMargins(18, 16, 18, 16)
        sc.setSpacing(10)
        sc.addWidget(section_label("Simulate Card Swipe"))

        row1 = QHBoxLayout()
        row1.setSpacing(10)
        self.swipe_student = StyledInput("Student ID  (e.g. STU-001)")
        self.swipe_room    = StyledCombo()
        self._load_rooms()
        swipe_btn = StyledButton("Simulate Swipe")
        swipe_btn.clicked.connect(self.do_swipe)
        row1.addWidget(self.swipe_student, 2)
        row1.addWidget(self.swipe_room, 2)
        row1.addWidget(swipe_btn, 1)
        sc.addLayout(row1)

        self.swipe_result = QLabel("")
        self.swipe_result.setVisible(False)
        self.swipe_result.setWordWrap(True)
        sc.addWidget(self.swipe_result)
        layout.addWidget(swipe_card)

        layout.addWidget(section_label("Admin Actions"))
        grid = QGridLayout()
        grid.setSpacing(12)

        grid.addWidget(self._action_card(
            "Block Student", "Student ID", StyledButton("Block", DANGER),
            lambda inp: self._simple_update(inp,
                "UPDATE students SET status='BLOCKED' WHERE student_id=?", "Student blocked.")
        ), 0, 0)

        grid.addWidget(self._action_card(
            "Unblock Student", "Student ID", StyledButton("Unblock", SUCCESS),
            lambda inp: self._simple_update(inp,
                "UPDATE students SET status='ACTIVE' WHERE student_id=?", "Student unblocked.")
        ), 0, 1)

        grid.addWidget(self._action_card(
            "Report Card Lost", "Student ID", StyledButton("Report Lost", WARNING),
            lambda inp: self._report_lost(inp)
        ), 1, 0)

        grid.addWidget(self._action_card(
            "Recover Lost Card", "Student ID", StyledButton("Recover Card", ACCENT),
            lambda inp: self._simple_update(inp,
                "UPDATE lost_cards SET status='RECOVERED' WHERE student_id=? AND status='LOST'",
                "Card marked as recovered.")
        ), 1, 1)

        grid.addWidget(self._action_card(
            "Resolve Alert", "Alert ID", StyledButton("Resolve", INFO),
            lambda inp: self._resolve_alert(inp)
        ), 2, 0)

        layout.addLayout(grid)
        layout.addStretch()

    def _load_rooms(self):
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute("SELECT room_id, room_name, required_level FROM rooms")
            for row in cur.fetchall():
                self.swipe_room.addItem(
                    f"{row['room_name']}  (Level {row['required_level']})",
                    userData=row['room_id']
                )
            conn.close()
        except:
            pass

    def _action_card(self, title, placeholder, btn, callback, extra=None):
        card = card_frame()
        cl   = QVBoxLayout(card)
        cl.setContentsMargins(14, 12, 14, 12)
        cl.setSpacing(8)
        lbl = QLabel(title)
        lbl.setFont(make_font(13, bold=True))
        lbl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        lbl.setStyleSheet(f"color:{TEXT_DARK}; border:none;")
        cl.addWidget(lbl)
        inp  = StyledInput(placeholder)
        inp2 = StyledInput(extra) if extra else None
        row  = QHBoxLayout()
        row.setSpacing(8)
        row.addWidget(inp)
        if inp2:
            row.addWidget(inp2)
        row.addWidget(btn)
        cl.addLayout(row)
        if extra:
            btn.clicked.connect(lambda: callback(inp, inp2))
        else:
            btn.clicked.connect(lambda: callback(inp))
        return card

    def do_swipe(self):
        sid = self.swipe_student.text().strip().upper()
        rid = self.swipe_room.currentData()
        if not sid:
            QMessageBox.warning(self, "Missing", "Please enter a Student ID.")
            return
        try:
            status, message = process_swipe(sid, rid)
            ok = status == 'GRANTED'
            bg = SUCCESS if ok else DANGER
            self.swipe_result.setText(f"Result: {status}\n{message}")
            self.swipe_result.setStyleSheet(f"""
                background: {bg}22; color: {bg};
                border-radius: 8px; padding: 10px;
                border: 1px solid {bg}44;
                font-size: 13px; font-weight: bold;
            """)
            self.swipe_result.setVisible(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _simple_update(self, inp, query, msg):
        val = inp.text().strip().upper()
        if not val:
            QMessageBox.warning(self, "Missing", "Please enter an ID.")
            return
        try:
            conn = get_connection()
            conn.execute(query, (val,))
            conn.commit(); conn.close()
            QMessageBox.information(self, "Done", msg)
            inp.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _report_lost(self, inp):
        sid = inp.text().strip().upper()
        if not sid:
            QMessageBox.warning(self, "Missing", "Please enter a Student ID.")
            return
        try:
            conn = get_connection()
            cur  = conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM lost_cards WHERE student_id=? AND status='LOST'", (sid,)
            )
            if cur.fetchone()[0] > 0:
                QMessageBox.warning(self, "Already", "Card is already reported as lost.")
                conn.close()
                return
            conn.execute("INSERT INTO lost_cards (student_id) VALUES (?)", (sid,))
            conn.commit(); conn.close()
            QMessageBox.information(self, "Done", "Card reported as lost.")
            inp.clear()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def _resolve_alert(self, inp):
        val = inp.text().strip()
        if not val:
            QMessageBox.warning(self, "Missing", "Please enter an Alert ID.")
            return
        try:
            conn = get_connection()
            conn.execute(
                "UPDATE security_alerts SET is_resolved=1 WHERE alert_id=?", (val,)
            )
            conn.commit(); conn.close()
            QMessageBox.information(self, "Done", "Alert resolved.")
            inp.clear()
            if self.alerts_screen:
                self.alerts_screen.load("all")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))



# ──────────────────────────────────────────────
# SIDEBAR NAV ITEM
# ──────────────────────────────────────────────

class NavItem(QFrame):
    def __init__(self, icon_text, label, on_click):
        super().__init__()
        self.on_click = on_click
        self.setCursor(Qt.PointingHandCursor)
        self._set_style(False)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 12, 20, 12)
        layout.setSpacing(12)

        self.icon = QLabel(icon_text)
        self.icon.setFont(make_font(15))
        self.icon.setStyleSheet("color: #9CA3AF; border: none;")
        self.icon.setFixedWidth(22)

        self.text = QLabel(label)
        self.text.setFont(make_font(13))
        self.text.setStyleSheet("color: #9CA3AF; border: none;")

        layout.addWidget(self.icon)
        layout.addWidget(self.text)

    def _set_style(self, active):
        bg = SIDEBAR_ITEM_ACTIVE if active else "transparent"
        self.setStyleSheet(f"""
            QFrame {{ background: {bg}; border-radius: 8px; margin: 2px 8px; }}
        """)

    def set_active(self, active):
        self._set_style(active)
        color = "#FFFFFF" if active else "#9CA3AF"
        self.icon.setStyleSheet(f"color: {color}; border: none;")
        self.text.setStyleSheet(f"color: {color}; border: none;")

    def mousePressEvent(self, e):
        self.on_click()


# ──────────────────────────────────────────────
# MAIN WINDOW
# ──────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self, username):
        super().__init__()
        self.setWindowTitle("SecureAccess — Admin Portal")
        self.setMinimumSize(1100, 680)

        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        sidebar = QFrame()
        sidebar.setFixedWidth(210)
        sidebar.setStyleSheet(f"background: {BG_SIDEBAR};")
        sb = QVBoxLayout(sidebar)
        sb.setContentsMargins(0, 0, 0, 0)
        sb.setSpacing(0)

        header = QFrame()
        header.setStyleSheet(f"background: {BG_SIDEBAR}; border-bottom: 1px solid #2D2D44;")
        hl = QVBoxLayout(header)
        hl.setContentsMargins(20, 18, 20, 16)
        t = QLabel("SecureAccess")
        t.setFont(make_font(16, bold=True))
        t.setStyleSheet("color: #FFFFFF; border: none;")
        s = QLabel("Admin Portal")
        s.setFont(make_font(11))
        s.setStyleSheet("color: #6B7280; border: none;")
        hl.addWidget(t); hl.addWidget(s)
        sb.addWidget(header)
        sb.addSpacing(10)

        self.stack      = QStackedWidget()
        self.screens    = {}
        self.nav_items  = []

        alerts_screen    = AlertsScreen()
        simulator_screen = SimulatorScreen(alerts_screen=alerts_screen)

        nav_defs = [
            ("▣", "Dashboard",   DashboardScreen()),
            ("◉", "Students",    StudentsScreen()),
            ("☰", "Access Logs", LogsScreen()),
            ("⚑", "Alerts",      alerts_screen),
            ("▷", "Simulator",   simulator_screen),
        ]

        for icon, label, screen in nav_defs:
            self.screens[label] = screen
            self.stack.addWidget(screen)
            item = NavItem(icon, label, lambda l=label: self.switch_screen(l))
            self.nav_items.append((label, item))
            sb.addWidget(item)

        sb.addStretch()

        footer = QFrame()
        footer.setStyleSheet(f"background: {BG_SIDEBAR}; border-top: 1px solid #2D2D44;")
        fl = QVBoxLayout(footer)
        fl.setContentsMargins(20, 12, 20, 12)
        u = QLabel(f"Logged in as: {username}")
        u.setFont(make_font(11))
        u.setStyleSheet("color: #6B7280; border: none;")
        fl.addWidget(u)
        sb.addWidget(footer)

        root.addWidget(sidebar)
        root.addWidget(self.stack)

        self.switch_screen("Dashboard")

    def switch_screen(self, name):
        for label, item in self.nav_items:
            item.set_active(label == name)
        self.stack.setCurrentWidget(self.screens[name])
        if name == "Dashboard":
            self.screens["Dashboard"].load_data()
        elif name == "Alerts":
            self.screens["Alerts"].load("all")
        elif name == "Access Logs":
            self.screens["Access Logs"].load("all")


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

def main():
    init_db()

    app = QApplication(sys.argv)
    app.setFont(QFont(FONT_FAMILY, 13))
    app.setStyle("Fusion")

    main_win = None

    def on_login(username):
        nonlocal main_win
        login_win.hide()
        main_win = MainWindow(username)
        main_win.show()

    login_win = QWidget()
    login_win.setWindowTitle("SecureAccess — Login")
    login_win.setFixedSize(460, 340)
    login_win.setStyleSheet(f"background: {BG_MAIN};")
    layout = QVBoxLayout(login_win)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(LoginScreen(on_login))
    login_win.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
