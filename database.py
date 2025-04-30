import os
import sqlite3
import json
import yaml
import logging
import time
from datetime import datetime, timedelta
from contextlib import contextmanager

# Set up logging
logger = logging.getLogger(__name__)

# Database file path
DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
DB_FILE = os.path.join(DB_DIR, 'certifly.db')

# Ensure the data directory exists
def ensure_db_dir():
    """Ensure the database directory exists"""
    if not os.path.exists(DB_DIR):
        try:
            os.makedirs(DB_DIR)
            logger.info(f"Created database directory: {DB_DIR}")
            return True
        except Exception as e:
            logger.error(f"Error creating database directory: {e}")
            return False
    return True

@contextmanager
def get_db_connection():
    """Get a database connection with context manager for automatic closing"""
    ensure_db_dir()
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE)
        conn.row_factory = sqlite3.Row  # Return rows as dictionaries
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Database error: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize the database with required tables"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1,
            last_login TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create sessions table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_token TEXT UNIQUE NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
        ''')

        # Create user_preferences table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_preferences (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            value TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            UNIQUE (user_id, key)
        )
        ''')

        # Create organizations table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create user_organizations table (many-to-many relationship)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            organization_id INTEGER NOT NULL,
            role TEXT NOT NULL DEFAULT 'member', -- 'admin', 'member'
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
            FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
            UNIQUE (user_id, organization_id)
        )
        ''')

        # Create tags table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            color TEXT DEFAULT '#6c757d',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
            UNIQUE (organization_id, name)
        )
        ''')

        # Create default organization if it doesn't exist
        cursor.execute("SELECT COUNT(*) as count FROM organizations")
        if cursor.fetchone()['count'] == 0:
            cursor.execute(
                "INSERT INTO organizations (id, name, description) VALUES (1, 'Default Organization', 'Default organization for all users')"
            )

        # Create domains table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            organization_id INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (organization_id) REFERENCES organizations (id) ON DELETE CASCADE,
            UNIQUE (name, organization_id)
        )
        ''')

        # Create domain_tags table (many-to-many relationship)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS domain_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            tag_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
            FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE,
            UNIQUE (domain_id, tag_id)
        )
        ''')

        # Create monitoring table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS monitoring (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            type TEXT NOT NULL,  -- 'ssl', 'expiry', 'ping'
            enabled INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE,
            UNIQUE (domain_id, type)
        )
        ''')

        # Create cache table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create settings table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create alerts table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            type TEXT NOT NULL,  -- 'ssl', 'expiry', 'ping'
            status TEXT NOT NULL,  -- 'warning', 'expired', 'error', 'down'
            message TEXT NOT NULL,
            acknowledged INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
        )
        ''')

        # Create alert_history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS alert_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id TEXT NOT NULL,  -- Alert ID from config (not database ID)
            domain_name TEXT NOT NULL,
            type TEXT NOT NULL,  -- 'ssl', 'expiry', 'ping'
            status TEXT NOT NULL,  -- 'warning', 'expired', 'error', 'down'
            message TEXT NOT NULL,
            action TEXT NOT NULL,  -- 'acknowledged', 'deleted', 'restored'
            user_id INTEGER,
            username TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')

        # Create ping_history table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS ping_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            status TEXT NOT NULL,  -- 'up', 'down', 'unknown'
            response_time REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (domain_id) REFERENCES domains (id) ON DELETE CASCADE
        )
        ''')

        conn.commit()
        logger.info("Database initialized successfully")

def migrate_config_to_db():
    """Migrate existing YAML config to SQLite database"""
    from app import load_config, CONFIG_FILE

    if not os.path.exists(CONFIG_FILE):
        logger.warning(f"Config file not found: {CONFIG_FILE}")
        return False

    try:
        # Load existing config
        config = load_config()

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Migrate SSL domains
            for entry in config.get('ssl_domains', []):
                domain_name = entry.get('url')
                if domain_name:
                    # Insert domain if it doesn't exist
                    cursor.execute(
                        "INSERT OR IGNORE INTO domains (name) VALUES (?)",
                        (domain_name,)
                    )

                    # Get domain ID
                    cursor.execute("SELECT id FROM domains WHERE name = ?", (domain_name,))
                    domain_id = cursor.fetchone()['id']

                    # Add SSL monitoring
                    cursor.execute(
                        "INSERT OR IGNORE INTO monitoring (domain_id, type) VALUES (?, ?)",
                        (domain_id, 'ssl')
                    )

            # Migrate domain expiry
            for entry in config.get('domain_expiry', []):
                domain_name = entry.get('name')
                if domain_name:
                    # Insert domain if it doesn't exist
                    cursor.execute(
                        "INSERT OR IGNORE INTO domains (name) VALUES (?)",
                        (domain_name,)
                    )

                    # Get domain ID
                    cursor.execute("SELECT id FROM domains WHERE name = ?", (domain_name,))
                    domain_id = cursor.fetchone()['id']

                    # Add expiry monitoring
                    cursor.execute(
                        "INSERT OR IGNORE INTO monitoring (domain_id, type) VALUES (?, ?)",
                        (domain_id, 'expiry')
                    )

            # Migrate ping hosts
            for entry in config.get('ping_hosts', []):
                domain_name = entry.get('host')
                if domain_name:
                    # Insert domain if it doesn't exist
                    cursor.execute(
                        "INSERT OR IGNORE INTO domains (name) VALUES (?)",
                        (domain_name,)
                    )

                    # Get domain ID
                    cursor.execute("SELECT id FROM domains WHERE name = ?", (domain_name,))
                    domain_id = cursor.fetchone()['id']

                    # Add ping monitoring
                    cursor.execute(
                        "INSERT OR IGNORE INTO monitoring (domain_id, type) VALUES (?, ?)",
                        (domain_id, 'ping')
                    )

            # Migrate notification settings
            if 'notifications' in config:
                notifications = config['notifications']
                cursor.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ('notifications', json.dumps(notifications))
                )

            # Migrate email settings
            if 'email' in config:
                email_settings = config['email']
                cursor.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ('email', json.dumps(email_settings))
                )

            # Migrate acknowledged alerts
            if 'acknowledged_alerts' in config:
                acknowledged_alerts = config['acknowledged_alerts']
                cursor.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    ('acknowledged_alerts', json.dumps(acknowledged_alerts))
                )

            conn.commit()
            logger.info("Configuration migrated to database successfully")
            return True
    except Exception as e:
        logger.error(f"Error migrating config to database: {e}")
        return False

# Domain operations
def get_domains(org_id=None):
    """Get all domains with their monitoring status

    Args:
        org_id (int, optional): Organization ID to filter by. If None, returns all domains.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        query = '''
        SELECT d.id, d.name, d.organization_id,
               MAX(CASE WHEN m.type = 'ssl' THEN 1 ELSE 0 END) as ssl_monitored,
               MAX(CASE WHEN m.type = 'expiry' THEN 1 ELSE 0 END) as expiry_monitored,
               MAX(CASE WHEN m.type = 'ping' THEN 1 ELSE 0 END) as ping_monitored
        FROM domains d
        LEFT JOIN monitoring m ON d.id = m.domain_id
        '''

        params = []
        if org_id is not None:
            query += 'WHERE d.organization_id = ? '
            params.append(org_id)

        query += '''
        GROUP BY d.id, d.name
        ORDER BY d.name
        '''

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def get_domain_by_id(domain_id):
    """Get a domain by ID with its monitoring status"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT d.id, d.name, d.organization_id,
               MAX(CASE WHEN m.type = 'ssl' THEN 1 ELSE 0 END) as ssl_monitored,
               MAX(CASE WHEN m.type = 'expiry' THEN 1 ELSE 0 END) as expiry_monitored,
               MAX(CASE WHEN m.type = 'ping' THEN 1 ELSE 0 END) as ping_monitored
        FROM domains d
        LEFT JOIN monitoring m ON d.id = m.domain_id
        WHERE d.id = ?
        GROUP BY d.id, d.name
        ''', (domain_id,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_domain_by_name(domain_name):
    """Get a domain by name with its monitoring status"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT d.id, d.name,
               MAX(CASE WHEN m.type = 'ssl' THEN 1 ELSE 0 END) as ssl_monitored,
               MAX(CASE WHEN m.type = 'expiry' THEN 1 ELSE 0 END) as expiry_monitored,
               MAX(CASE WHEN m.type = 'ping' THEN 1 ELSE 0 END) as ping_monitored
        FROM domains d
        LEFT JOIN monitoring m ON d.id = m.domain_id
        WHERE d.name = ?
        GROUP BY d.id, d.name
        ''', (domain_name,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_domain_by_name_and_org(domain_name, org_id):
    """Get a domain by name and organization ID with its monitoring status"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
        SELECT d.id, d.name, d.organization_id,
               MAX(CASE WHEN m.type = 'ssl' THEN 1 ELSE 0 END) as ssl_monitored,
               MAX(CASE WHEN m.type = 'expiry' THEN 1 ELSE 0 END) as expiry_monitored,
               MAX(CASE WHEN m.type = 'ping' THEN 1 ELSE 0 END) as ping_monitored
        FROM domains d
        LEFT JOIN monitoring m ON d.id = m.domain_id
        WHERE d.name = ? AND d.organization_id = ?
        GROUP BY d.id, d.name
        ''', (domain_name, org_id))
        result = cursor.fetchone()
        return dict(result) if result else None

def add_domain(domain_name, organization_id, monitor_ssl=False, monitor_expiry=False, monitor_ping=False):
    """Add a new domain with specified monitoring types"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Insert domain
            cursor.execute(
                "INSERT INTO domains (name, organization_id) VALUES (?, ?)",
                (domain_name, organization_id)
            )
            domain_id = cursor.lastrowid

            # Add monitoring types
            if monitor_ssl:
                cursor.execute(
                    "INSERT INTO monitoring (domain_id, type) VALUES (?, ?)",
                    (domain_id, 'ssl')
                )

            if monitor_expiry:
                cursor.execute(
                    "INSERT INTO monitoring (domain_id, type) VALUES (?, ?)",
                    (domain_id, 'expiry')
                )

            if monitor_ping:
                cursor.execute(
                    "INSERT INTO monitoring (domain_id, type) VALUES (?, ?)",
                    (domain_id, 'ping')
                )

            conn.commit()
            return domain_id
        except sqlite3.IntegrityError:
            # Domain already exists
            conn.rollback()
            return None

def update_domain(domain_id, new_name=None, monitor_ssl=None, monitor_expiry=None, monitor_ping=None):
    """Update a domain and its monitoring settings"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Update domain name if provided
            if new_name:
                cursor.execute(
                    "UPDATE domains SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (new_name, domain_id)
                )

            # Update monitoring settings if provided
            if monitor_ssl is not None:
                if monitor_ssl:
                    cursor.execute(
                        "INSERT OR IGNORE INTO monitoring (domain_id, type) VALUES (?, ?)",
                        (domain_id, 'ssl')
                    )
                else:
                    cursor.execute(
                        "DELETE FROM monitoring WHERE domain_id = ? AND type = ?",
                        (domain_id, 'ssl')
                    )

            if monitor_expiry is not None:
                if monitor_expiry:
                    cursor.execute(
                        "INSERT OR IGNORE INTO monitoring (domain_id, type) VALUES (?, ?)",
                        (domain_id, 'expiry')
                    )
                else:
                    cursor.execute(
                        "DELETE FROM monitoring WHERE domain_id = ? AND type = ?",
                        (domain_id, 'expiry')
                    )

            if monitor_ping is not None:
                if monitor_ping:
                    cursor.execute(
                        "INSERT OR IGNORE INTO monitoring (domain_id, type) VALUES (?, ?)",
                        (domain_id, 'ping')
                    )
                else:
                    cursor.execute(
                        "DELETE FROM monitoring WHERE domain_id = ? AND type = ?",
                        (domain_id, 'ping')
                    )

            conn.commit()
            return True
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error updating domain: {e}")
            return False

def delete_domain(domain_id):
    """Delete a domain and all its monitoring settings"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Delete domain (cascade will delete monitoring entries)
            cursor.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting domain: {e}")
            return False

# Cache operations
def set_cache(key, value, expires_in_seconds):
    """Set a cache value with expiration time"""
    expires_at = datetime.now().timestamp() + expires_in_seconds

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Convert value to JSON string if it's not already a string
            if not isinstance(value, str):
                value = json.dumps(value)

            cursor.execute(
                "INSERT OR REPLACE INTO cache (key, value, expires_at, updated_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)",
                (key, value, expires_at)
            )
            conn.commit()
            return True
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error setting cache: {e}")
            return False

def get_cache(key):
    """Get a cache value if it exists and is not expired"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT value, expires_at FROM cache WHERE key = ?",
            (key,)
        )
        result = cursor.fetchone()

        if result:
            # Check if expired
            if result['expires_at'] > datetime.now().timestamp():
                try:
                    # Try to parse as JSON
                    return json.loads(result['value'])
                except json.JSONDecodeError:
                    # Return as string if not valid JSON
                    return result['value']
            else:
                # Delete expired cache entry
                cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
                conn.commit()

        return None

def get_cache_metadata(key):
    """Get metadata about a cache entry without checking expiration"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT created_at, updated_at, expires_at FROM cache WHERE key = ?",
            (key,)
        )
        result = cursor.fetchone()

        if result:
            return dict(result)

        return None

def delete_cache(key):
    """Delete a cache entry"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM cache WHERE key = ?", (key,))
        conn.commit()
        return cursor.rowcount > 0

def clear_expired_cache():
    """Clear all expired cache entries"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM cache WHERE expires_at < ?",
            (datetime.now().timestamp(),)
        )
        conn.commit()
        return cursor.rowcount

def clear_cache_by_prefix(prefix):
    """Clear all cache entries that start with the given prefix"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "DELETE FROM cache WHERE key LIKE ?",
            (f"{prefix}%",)
        )
        conn.commit()
        return cursor.rowcount

# Settings operations
def get_setting(key, default=None):
    """Get a setting value"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
        result = cursor.fetchone()

        if result:
            try:
                # Try to parse as JSON
                return json.loads(result['value'])
            except json.JSONDecodeError:
                # Return as string if not valid JSON
                return result['value']

        return default

def set_setting(key, value):
    """Set a setting value"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Convert value to JSON string if it's not already a string
            if not isinstance(value, str):
                value = json.dumps(value)

            cursor.execute(
                "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
                (key, value)
            )
            conn.commit()
            return True
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error setting setting: {e}")
            return False

# User operations
def create_user(username, email, password_hash, is_admin=False):
    """Create a new user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, ?)",
                (username, email, password_hash, 1 if is_admin else 0)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            # Username or email already exists
            conn.rollback()
            logger.error(f"User with username '{username}' or email '{email}' already exists")
            return None
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error creating user: {e}")
            return None

def get_user_by_username(username):
    """Get a user by username"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_user_by_email(email):
    """Get a user by email"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_user_by_id(user_id):
    """Get a user by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_users_by_partial_username(query):
    """Get users by partial username match"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Log the query for debugging
            logger.debug(f"Searching for users with query: '{query}'")

            # Use case-insensitive search
            cursor.execute("SELECT id, username, email FROM users WHERE username LIKE ? COLLATE NOCASE LIMIT 10", (f"%{query}%",))
            users = cursor.fetchall()

            # Convert to list of dictionaries
            result = [dict(user) for user in users]
            logger.debug(f"Found {len(result)} users matching '{query}': {[user['username'] for user in result]}")

            return result
        except Exception as e:
            logger.error(f"Error in get_users_by_partial_username: {str(e)}")
            return []

def search_users(search_term):
    """Search for users by username or email"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Use LIKE for case-insensitive search
            search_pattern = f"%{search_term}%"
            cursor.execute("""
                SELECT id, username, email, is_admin, is_active
                FROM users
                WHERE username LIKE ? OR email LIKE ?
                ORDER BY username
                LIMIT 10
            """, (search_pattern, search_pattern))
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Error in search_users: {str(e)}")
            return []

def get_all_users():
    """Get all users with their organization memberships"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        # First get all users
        cursor.execute("""
            SELECT id, username, email, is_admin, is_active,
                   last_login, created_at, updated_at
            FROM users
            ORDER BY username
        """)
        users = [dict(row) for row in cursor.fetchall()]

        # For each user, get their organization memberships
        for user in users:
            cursor.execute("""
                SELECT o.id, o.name, uo.role
                FROM organizations o
                JOIN user_organizations uo ON o.id = uo.organization_id
                WHERE uo.user_id = ?
                ORDER BY o.name
            """, (user['id'],))
            user['organizations'] = [dict(row) for row in cursor.fetchall()]

        return users

def update_user(user_id, username=None, email=None, password_hash=None, is_admin=None, is_active=None):
    """Update a user's information"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # Build the SET clause dynamically based on provided parameters
        set_clauses = []
        params = []

        if username is not None:
            set_clauses.append("username = ?")
            params.append(username)

        if email is not None:
            set_clauses.append("email = ?")
            params.append(email)

        if password_hash is not None:
            set_clauses.append("password_hash = ?")
            params.append(password_hash)

        if is_admin is not None:
            set_clauses.append("is_admin = ?")
            params.append(1 if is_admin else 0)

        if is_active is not None:
            set_clauses.append("is_active = ?")
            params.append(1 if is_active else 0)

        # Add updated_at timestamp
        set_clauses.append("updated_at = ?")
        params.append(time.time())

        # Add user_id to params
        params.append(user_id)

        # Execute the update query
        if set_clauses:
            query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?"
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0

        return False

def delete_user(user_id):
    """Delete a user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # First delete all sessions for this user
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))

        # Then delete the user
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount > 0

def delete_user_sessions(user_id):
    """Delete all sessions for a user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        conn.commit()
        return cursor.rowcount

def update_last_login(user_id):
    """Update a user's last login timestamp"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error updating last login: {e}")
            return False

def delete_user(user_id):
    """Delete a user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting user: {e}")
            return False

# Ping history operations
def record_ping_status(domain_name, status, response_time=None, organization_id=1):
    """Record a ping status check in the history"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Get domain ID
            cursor.execute("SELECT id FROM domains WHERE name = ? AND organization_id = ?", (domain_name, organization_id))
            result = cursor.fetchone()
            if not result:
                # Domain doesn't exist, create it
                cursor.execute("INSERT INTO domains (name, organization_id) VALUES (?, ?)", (domain_name, organization_id))
                domain_id = cursor.lastrowid

                # Add ping monitoring
                cursor.execute(
                    "INSERT INTO monitoring (domain_id, type) VALUES (?, ?)",
                    (domain_id, 'ping')
                )
            else:
                domain_id = result['id']

            # Record ping status
            cursor.execute(
                "INSERT INTO ping_history (domain_id, status, response_time) VALUES (?, ?, ?)",
                (domain_id, status, response_time)
            )
            conn.commit()
            return True
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error recording ping status: {e}")
            return False

def get_ping_history(domain_name, hours=24):
    """Get ping history for a domain for the specified number of hours"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Get domain ID
            cursor.execute("SELECT id FROM domains WHERE name = ?", (domain_name,))
            result = cursor.fetchone()
            if not result:
                return []

            domain_id = result['id']

            # Get ping history
            cursor.execute(
                """
                SELECT status, response_time, timestamp
                FROM ping_history
                WHERE domain_id = ? AND timestamp >= datetime('now', ?)
                ORDER BY timestamp ASC
                """,
                (domain_id, f"-{hours} hours")
            )

            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error getting ping history: {e}")
            return []

def get_ping_response_history(domain_name, hours=24):
    """Get ping response time history for a domain within a specific timeframe

    Args:
        domain_name: The domain name to get history for
        hours: Number of hours to look back (default: 24)

    Returns:
        List of dictionaries with timestamp (milliseconds since epoch) and response_time
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Get domain ID
            cursor.execute("SELECT id FROM domains WHERE name = ?", (domain_name,))
            result = cursor.fetchone()
            if not result:
                logger.warning(f"Domain not found: {domain_name}")
                return []

            domain_id = result['id']

            # Calculate the timestamp for 'hours' ago
            time_ago = (datetime.now() - timedelta(hours=hours)).strftime('%Y-%m-%d %H:%M:%S')

            logger.debug(f"Getting ping history for domain {domain_name} (ID: {domain_id}) from {time_ago}")

            # Get ping history with response times within the timeframe
            cursor.execute(
                """
                SELECT response_time, timestamp
                FROM ping_history
                WHERE domain_id = ? AND status = 'up' AND response_time IS NOT NULL
                AND timestamp >= ?
                ORDER BY timestamp ASC
                """,
                (domain_id, time_ago)
            )

            results = cursor.fetchall()
            logger.debug(f"Found {len(results)} ping history records")

            # Format for chart display
            formatted_results = []
            for row in results:
                try:
                    # Parse the timestamp and convert to milliseconds for Chart.js
                    timestamp_str = row['timestamp']
                    dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')

                    # Convert to milliseconds timestamp for Chart.js time scale
                    timestamp_ms = int(dt.timestamp() * 1000)

                    # Ensure response_time is a valid float
                    response_time = 0
                    if row['response_time'] is not None:
                        try:
                            response_time = float(row['response_time'])
                        except (ValueError, TypeError):
                            logger.warning(f"Invalid response time value: {row['response_time']}")

                    formatted_results.append({
                        'timestamp': timestamp_ms,  # Use milliseconds timestamp for Chart.js
                        'response_time': response_time
                    })
                except Exception as e:
                    logger.error(f"Error formatting timestamp {row['timestamp']}: {e}")

            logger.debug(f"Returning {len(formatted_results)} formatted ping history records")
            return formatted_results
        except sqlite3.Error as e:
            logger.error(f"Error getting ping response history: {e}")
            return []

def calculate_uptime_percentage(domain_name, hours=24):
    """Calculate uptime percentage for a domain over the specified period"""
    history = get_ping_history(domain_name, hours)

    if not history:
        return None

    total_checks = len(history)
    up_checks = sum(1 for check in history if check['status'] == 'up')

    if total_checks == 0:
        return None

    return (up_checks / total_checks) * 100

# Session operations
def create_session(user_id, session_token, expires_at):
    """Create a new session"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
                (user_id, session_token, expires_at)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error creating session: {e}")
            return None

def get_session(session_token):
    """Get a session by token"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM sessions WHERE session_token = ? AND expires_at > ?",
            (session_token, datetime.now().timestamp())
        )
        result = cursor.fetchone()
        return dict(result) if result else None

def delete_session(session_token):
    """Delete a session"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting session: {e}")
            return False

def delete_user_sessions(user_id):
    """Delete all sessions for a user"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting user sessions: {e}")
            return False

# Organization operations
def create_organization(name, description=None):
    """Create a new organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO organizations (name, description) VALUES (?, ?)",
                (name, description)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error creating organization: {e}")
            return None

def get_organization(org_id):
    """Get organization by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations WHERE id = ?", (org_id,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_organization_by_name(name):
    """Get organization by name"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations WHERE name = ?", (name,))
        result = cursor.fetchone()
        return dict(result) if result else None

def update_organization(org_id, name=None, description=None):
    """Update an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Build the SET clause dynamically based on provided parameters
            set_clauses = []
            params = []

            if name is not None:
                set_clauses.append("name = ?")
                params.append(name)

            if description is not None:
                set_clauses.append("description = ?")
                params.append(description)

            # Add updated_at timestamp
            set_clauses.append("updated_at = CURRENT_TIMESTAMP")

            # Add org_id to params
            params.append(org_id)

            # Execute the update query
            if set_clauses:
                query = f"UPDATE organizations SET {', '.join(set_clauses)} WHERE id = ?"
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0
            return False
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error updating organization: {e}")
            return False

def delete_organization(org_id):
    """Delete an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM organizations WHERE id = ?", (org_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting organization: {e}")
            return False

def get_all_organizations():
    """Get all organizations"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM organizations ORDER BY name")
        return [dict(row) for row in cursor.fetchall()]

# User-Organization operations
def add_user_to_organization(user_id, org_id, role='member'):
    """Add a user to an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO user_organizations (user_id, organization_id, role) VALUES (?, ?, ?)",
                (user_id, org_id, role)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error adding user to organization: {e}")
            return None

def remove_user_from_organization(user_id, org_id):
    """Remove a user from an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM user_organizations WHERE user_id = ? AND organization_id = ?",
                (user_id, org_id)
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error removing user from organization: {e}")
            return False

def update_user_organization_role(user_id, org_id, role):
    """Update a user's role in an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE user_organizations SET role = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND organization_id = ?",
                (role, user_id, org_id)
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error updating user organization role: {e}")
            return False

def get_user_organizations(user_id):
    """Get all organizations a user belongs to"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT o.*, uo.role
            FROM organizations o
            JOIN user_organizations uo ON o.id = uo.organization_id
            WHERE uo.user_id = ?
            ORDER BY o.name
        ''', (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_organization_users(org_id):
    """Get all users in an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT u.id, u.username, u.email, u.is_admin, uo.role
            FROM users u
            JOIN user_organizations uo ON u.id = uo.user_id
            WHERE uo.organization_id = ?
            ORDER BY u.username
        ''', (org_id,))
        return [dict(row) for row in cursor.fetchall()]

def is_user_in_organization(user_id, org_id):
    """Check if a user is in an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM user_organizations WHERE user_id = ? AND organization_id = ?",
            (user_id, org_id)
        )
        return cursor.fetchone() is not None

def get_user_organization_role(user_id, org_id):
    """Get a user's role in an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT role FROM user_organizations WHERE user_id = ? AND organization_id = ?",
            (user_id, org_id)
        )
        result = cursor.fetchone()
        return result['role'] if result else None

# Tag operations
def create_tag(org_id, name, color='#6c757d'):
    """Create a new tag"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO tags (organization_id, name, color) VALUES (?, ?, ?)",
                (org_id, name, color)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error creating tag: {e}")
            return None

def get_tag(tag_id):
    """Get tag by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tags WHERE id = ?", (tag_id,))
        result = cursor.fetchone()
        return dict(result) if result else None

def update_tag(tag_id, name=None, color=None):
    """Update a tag"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Build the SET clause dynamically based on provided parameters
            set_clauses = []
            params = []

            if name is not None:
                set_clauses.append("name = ?")
                params.append(name)

            if color is not None:
                set_clauses.append("color = ?")
                params.append(color)

            # Add updated_at timestamp
            set_clauses.append("updated_at = CURRENT_TIMESTAMP")

            # Add tag_id to params
            params.append(tag_id)

            # Execute the update query
            if set_clauses:
                query = f"UPDATE tags SET {', '.join(set_clauses)} WHERE id = ?"
                cursor.execute(query, params)
                conn.commit()
                return cursor.rowcount > 0
            return False
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error updating tag: {e}")
            return False

def delete_tag(tag_id):
    """Delete a tag"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting tag: {e}")
            return False

def get_organization_tags(org_id):
    """Get all tags for an organization"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tags WHERE organization_id = ? ORDER BY name", (org_id,))
        return [dict(row) for row in cursor.fetchall()]

# Domain-Tag operations
def add_tag_to_domain(domain_id, tag_id):
    """Add a tag to a domain"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO domain_tags (domain_id, tag_id) VALUES (?, ?)",
                (domain_id, tag_id)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error adding tag to domain: {e}")
            return None

def remove_tag_from_domain(domain_id, tag_id):
    """Remove a tag from a domain"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM domain_tags WHERE domain_id = ? AND tag_id = ?",
                (domain_id, tag_id)
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error removing tag from domain: {e}")
            return False

def get_domain_tags(domain_id):
    """Get all tags for a domain"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT t.*
            FROM tags t
            JOIN domain_tags dt ON t.id = dt.tag_id
            WHERE dt.domain_id = ?
            ORDER BY t.name
        ''', (domain_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_domains_by_tag(tag_id):
    """Get all domains with a specific tag"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.*
            FROM domains d
            JOIN domain_tags dt ON d.id = dt.domain_id
            WHERE dt.tag_id = ?
            ORDER BY d.name
        ''', (tag_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_domains_by_organization(org_id):
    """Get all domains for a specific organization with their monitoring status"""
    return get_domains(org_id)

def get_domains_by_organization_and_tag(org_id, tag_id):
    """Get all domains for a specific organization with a specific tag"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.id, d.name, d.organization_id,
                   MAX(CASE WHEN m.type = 'ssl' THEN 1 ELSE 0 END) as ssl_monitored,
                   MAX(CASE WHEN m.type = 'expiry' THEN 1 ELSE 0 END) as expiry_monitored,
                   MAX(CASE WHEN m.type = 'ping' THEN 1 ELSE 0 END) as ping_monitored
            FROM domains d
            JOIN domain_tags dt ON d.id = dt.domain_id
            LEFT JOIN monitoring m ON d.id = m.domain_id
            WHERE d.organization_id = ? AND dt.tag_id = ?
            GROUP BY d.id, d.name
            ORDER BY d.name
        ''', (org_id, tag_id))
        return [dict(row) for row in cursor.fetchall()]

def get_domain_by_id(domain_id):
    """Get domain by ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.*,
                   MAX(CASE WHEN m.type = 'ssl' THEN 1 ELSE 0 END) as ssl_monitored,
                   MAX(CASE WHEN m.type = 'expiry' THEN 1 ELSE 0 END) as expiry_monitored,
                   MAX(CASE WHEN m.type = 'ping' THEN 1 ELSE 0 END) as ping_monitored
            FROM domains d
            LEFT JOIN monitoring m ON d.id = m.domain_id
            WHERE d.id = ?
            GROUP BY d.id
        ''', (domain_id,))
        result = cursor.fetchone()
        return dict(result) if result else None

def get_all_domains():
    """Get all domains in the database"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT d.id, d.name, d.organization_id,
                   MAX(CASE WHEN m.type = 'ssl' THEN 1 ELSE 0 END) as ssl_monitored,
                   MAX(CASE WHEN m.type = 'expiry' THEN 1 ELSE 0 END) as expiry_monitored,
                   MAX(CASE WHEN m.type = 'ping' THEN 1 ELSE 0 END) as ping_monitored
            FROM domains d
            LEFT JOIN monitoring m ON d.id = m.domain_id
            GROUP BY d.id, d.name
            ORDER BY d.name
        ''')
        domains = cursor.fetchall()
        return [dict(row) for row in domains]

def update_domain(domain_id, name, monitor_ssl=False, monitor_expiry=False, monitor_ping=False):
    """Update a domain"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Update domain name
            cursor.execute(
                "UPDATE domains SET name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (name, domain_id)
            )

            # Delete existing monitoring entries
            cursor.execute("DELETE FROM monitoring WHERE domain_id = ?", (domain_id,))

            # Add new monitoring entries
            if monitor_ssl:
                cursor.execute(
                    "INSERT INTO monitoring (domain_id, type) VALUES (?, 'ssl')",
                    (domain_id,)
                )

            if monitor_expiry:
                cursor.execute(
                    "INSERT INTO monitoring (domain_id, type) VALUES (?, 'expiry')",
                    (domain_id,)
                )

            if monitor_ping:
                cursor.execute(
                    "INSERT INTO monitoring (domain_id, type) VALUES (?, 'ping')",
                    (domain_id,)
                )

            conn.commit()
            return True
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error updating domain: {e}")
            return False

def delete_domain(domain_id):
    """Delete a domain"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Delete domain (cascade will delete monitoring and tags)
            cursor.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting domain: {e}")
            return False

def clear_expired_sessions():
    """Clear all expired sessions"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "DELETE FROM sessions WHERE expires_at < ?",
                (datetime.now().timestamp(),)
            )
            conn.commit()
            return cursor.rowcount
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error clearing expired sessions: {e}")
            return 0

# Alert operations
def add_alert(domain_id, alert_type, status, message):
    """Add a new alert"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO alerts (domain_id, type, status, message) VALUES (?, ?, ?, ?)",
                (domain_id, alert_type, status, message)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error adding alert: {e}")
            return None

def get_alerts(include_acknowledged=False, days=None):
    """Get all alerts, optionally including acknowledged ones and within a time range"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
        SELECT a.id, a.domain_id, d.name as domain_name, a.type as alert_type, a.status, a.message,
               a.acknowledged, a.created_at, a.updated_at
        FROM alerts a
        JOIN domains d ON a.domain_id = d.id
        """

        conditions = []
        params = []

        if not include_acknowledged:
            conditions.append("a.acknowledged = 0")

        if days is not None:
            cutoff_date = (datetime.now() - timedelta(days=days)).timestamp()
            conditions.append("a.created_at >= ?")
            params.append(cutoff_date)

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY a.created_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def get_alerts_by_type(alert_type, days=None):
    """Get alerts of a specific type within a time range"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
        SELECT a.id, a.domain_id, d.name as domain, a.type as alert_type, a.status, a.message,
               a.acknowledged, a.created_at, a.updated_at
        FROM alerts a
        JOIN domains d ON a.domain_id = d.id
        WHERE a.type = ?
        """

        params = [alert_type]

        if days is not None:
            cutoff_date = (datetime.now() - timedelta(days=days)).timestamp()
            query += " AND a.created_at >= ?"
            params.append(cutoff_date)

        query += " ORDER BY a.created_at DESC"

        cursor.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def get_alerts_by_domain(domain_name, limit=None):
    """Get alerts for a specific domain"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
        SELECT a.id, a.domain_id, d.name as domain, a.type as alert_type, a.status, a.message,
               a.acknowledged, a.created_at, a.updated_at
        FROM alerts a
        JOIN domains d ON a.domain_id = d.id
        WHERE d.name = ?
        ORDER BY a.created_at DESC
        """

        if limit is not None:
            query += " LIMIT ?"
            cursor.execute(query, (domain_name, limit))
        else:
            cursor.execute(query, (domain_name,))

        return [dict(row) for row in cursor.fetchall()]

def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "UPDATE alerts SET acknowledged = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (alert_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error acknowledging alert: {e}")
            return False

def delete_alert(alert_id):
    """Delete an alert"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
            conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error deleting alert: {e}")
            return False

# Alert History operations
def add_alert_history(alert_id, domain_name, alert_type, status, message, action, user_id=None, username=None):
    """Add an entry to the alert history"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO alert_history
                (alert_id, domain_name, type, status, message, action, user_id, username)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (alert_id, domain_name, alert_type, status, message, action, user_id, username)
            )
            conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            conn.rollback()
            logger.error(f"Error adding alert history: {e}")
            return None

def get_alert_history(limit=None, offset=0):
    """Get alert history with pagination"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        query = """
        SELECT id, alert_id, domain_name, type, status, message, action, user_id, username,
               datetime(created_at, 'localtime') as created_at
        FROM alert_history
        ORDER BY created_at DESC
        """

        if limit is not None:
            query += f" LIMIT {limit} OFFSET {offset}"

        cursor.execute(query)
        return [dict(row) for row in cursor.fetchall()]

def get_alert_history_count():
    """Get the total count of alert history entries"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM alert_history")
        result = cursor.fetchone()
        return result['count'] if result else 0

# Initialize database
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Initialize database
    init_db()

    # Migrate existing config
    migrate_config_to_db()
