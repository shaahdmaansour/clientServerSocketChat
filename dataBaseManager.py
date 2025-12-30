from datetime import datetime
import os
import sqlite3

class DatabaseManager:
    def __init__(self, db_path=None):
        """
        Database manager using SQLite for message persistence.

        db_path: optional path to sqlite file (for testing or custom location).
        """
        # SQLite database for message persistence
        default_dir = os.path.dirname(os.path.abspath(__file__))
        if db_path is None:
            db_path = os.path.join(default_dir, "chat_local.db")
        try:
            os.makedirs(os.path.dirname(db_path) or default_dir, exist_ok=True)
            # ensure file exists (create if missing)
            try:
                open(db_path, "a").close()
            except Exception:
                pass
            self.sqlite_conn = sqlite3.connect(db_path, check_same_thread=False)
        except Exception as e:
            print(f"Warning: cannot open sqlite db file {db_path}: {e}. Falling back to in-memory DB.")
            self.sqlite_conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._ensure_sqlite_schema()

    def _ensure_sqlite_schema(self):
        cur = self.sqlite_conn.cursor()
        # Ensure messages table exists and includes a 'delivered' column for private messages
        cur.execute('''CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            message TEXT,
            is_private INTEGER,
            recipient TEXT,
            timestamp TEXT,
            delivered INTEGER DEFAULT 0
        )''')
        # Last seen tracking for users (for missed public messages)
        cur.execute('''CREATE TABLE IF NOT EXISTS user_last_seen (
            username TEXT PRIMARY KEY,
            last_seen TEXT
        )''')
        # If older schema missing 'delivered', add it
        cur.execute("PRAGMA table_info(messages)")
        cols = [r[1] for r in cur.fetchall()]
        if 'delivered' not in cols:
            try:
                cur.execute("ALTER TABLE messages ADD COLUMN delivered INTEGER DEFAULT 0")
            except Exception:
                pass
        self.sqlite_conn.commit()

    def save_message(self, sender, message, is_private=False, recipient=None, delivered=False):
        """Save a message to the SQLite database."""
        try:
            cur = self.sqlite_conn.cursor()
            cur.execute(
                "INSERT INTO messages (sender,message,is_private,recipient,timestamp,delivered) VALUES (?,?,?,?,?,?)",
                (sender, message, int(is_private), recipient, datetime.now().isoformat(), int(delivered))
            )
            self.sqlite_conn.commit()
        except Exception as e:
            print(f"SQLite save error: {e}")

    def get_undelivered_messages(self, recipient):
        """Return list of undelivered messages for recipient (private messages only)."""
        try:
            cur = self.sqlite_conn.cursor()
            cur.execute("SELECT id, sender, message, is_private, recipient, timestamp FROM messages WHERE recipient=? AND delivered=0",
                        (recipient,))
            rows = cur.fetchall()
            return [{"id": r[0], "sender": r[1], "message": r[2], "is_private": bool(r[3]), "recipient": r[4], "timestamp": r[5]} for r in rows]
        except Exception as e:
            print(f"SQLite fetch undelivered error: {e}")
            return []

    def set_last_seen(self, username, when=None):
        """Update last_seen for a user (when defaults to now)."""
        try:
            when = when or datetime.now().isoformat()
            cur = self.sqlite_conn.cursor()
            cur.execute("INSERT INTO user_last_seen (username,last_seen) VALUES (?,?) ON CONFLICT(username) DO UPDATE SET last_seen=excluded.last_seen",
                        (username, when))
            self.sqlite_conn.commit()
        except Exception as e:
            print(f"SQLite set_last_seen error: {e}")

    def get_last_seen(self, username):
        try:
            cur = self.sqlite_conn.cursor()
            cur.execute("SELECT last_seen FROM user_last_seen WHERE username=?", (username,))
            r = cur.fetchone()
            return r[0] if r else None
        except Exception as e:
            print(f"SQLite get_last_seen error: {e}")
            return None

    def get_public_messages_since(self, since_iso):
        """Return public (non-private) messages since `since_iso` timestamp."""
        try:
            cur = self.sqlite_conn.cursor()
            cur.execute("SELECT id, sender, message, timestamp FROM messages WHERE is_private=0 AND timestamp>? ORDER BY timestamp ASC", (since_iso,))
            rows = cur.fetchall()
            return [{"id": r[0], "sender": r[1], "message": r[2], "timestamp": r[3]} for r in rows]
        except Exception as e:
            print(f"SQLite fetch public since error: {e}")
            return []

    def mark_messages_delivered(self, ids):
        try:
            cur = self.sqlite_conn.cursor()
            cur.executemany("UPDATE messages SET delivered=1 WHERE id=?", [(i,) for i in ids])
            self.sqlite_conn.commit()
        except Exception as e:
            print(f"SQLite mark delivered error: {e}")

    def get_chat_history(self, user, limit=50):
        """Get chat history for a user from SQLite database."""
        try:
            cur = self.sqlite_conn.cursor()
            cur.execute("""SELECT sender,message,is_private,recipient,timestamp FROM messages
                           WHERE is_private=0 OR recipient=? OR sender=?
                           ORDER BY timestamp DESC LIMIT ?""", (user, user, limit))
            rows = cur.fetchall()
            return [{"sender": r[0], "message": r[1], "is_private": bool(r[2]), "recipient": r[3], "timestamp": r[4]} for r in rows]
        except Exception as e:
            print(f"SQLite fetch error: {e}")
            return []

    def clear_chat_history(self):
        """Clear all messages and user tracking data from the SQLite database."""
        try:
            cur = self.sqlite_conn.cursor()
            # Clear all messages
            cur.execute("DELETE FROM messages")
            # Clear user last seen tracking
            cur.execute("DELETE FROM user_last_seen")
            self.sqlite_conn.commit()
        except Exception as e:
            print(f"Error clearing chat history: {e}")