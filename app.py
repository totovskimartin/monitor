from flask import Flask, render_template, request, flash, redirect, url_for, send_file, jsonify, make_response, session, Response
import yaml
import subprocess
from datetime import datetime, timedelta
import os
import shutil
import re
import json
import time
import requests
import logging
import io
import csv
import threading
from logging.handlers import RotatingFileHandler

from dataclasses import dataclass, field
from notifications import send_test_notification, send_certificate_expiry_notification, send_domain_expiry_notification

# Set up logging
def setup_logging():
    """Configure application logging"""
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, 'certifly.log')

    # Create a logger
    logger = logging.getLogger('certifly')
    logger.setLevel(logging.INFO)

    # Create handlers
    file_handler = RotatingFileHandler(log_file, maxBytes=1024*1024*5, backupCount=5)
    console_handler = logging.StreamHandler()

    # Create formatters
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# Initialize logger
logger = setup_logging()

@dataclass
class CertificateStatus:
    domain: str
    days_remaining: int
    expiry_date: datetime
    status: str  # 'valid', 'warning', 'expired'
    ping_status: str = "unknown"  # 'up', 'down', 'unknown'

    def __post_init__(self):
        # Ensure days_remaining is an integer
        try:
            self.days_remaining = int(self.days_remaining)
        except (ValueError, TypeError):
            logger.warning(f"Invalid days_remaining for {self.domain}: {self.days_remaining}. Setting to -1.")
            self.days_remaining = -1

@dataclass
class DomainStatus:
    name: str
    days_remaining: int
    expiry_date: datetime
    registrar: str
    status: str  # 'valid', 'warning', 'expired', 'error'
    ping_status: str = "unknown"  # 'up', 'down', 'unknown'

    def __post_init__(self):
        # Ensure days_remaining is an integer
        try:
            self.days_remaining = int(self.days_remaining)
        except (ValueError, TypeError):
            logger.warning(f"Invalid days_remaining for {self.name}: {self.days_remaining}. Setting to -1.")
            self.days_remaining = -1

@dataclass
class PingStatus:
    """Ping monitoring status"""
    host: str
    status: str  # 'up', 'down', 'unknown'
    last_checked: datetime = None
    response_time: float = 0.0  # in milliseconds
    response_history: list = field(default_factory=list)  # List of recent response times

# Ping cache
PING_CACHE = {}
PING_CACHE_EXPIRY = 300  # 5 minutes in seconds

def load_ping_cache():
    """Load the ping cache from disk"""
    cache_file = os.path.join(DATA_DIR, "ping_cache.json")
    if not os.path.exists(cache_file):
        return {}

    try:
        with open(cache_file, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading ping cache: {e}")
        return {}

def save_ping_cache(cache_data):
    """Save the ping cache to disk"""
    if not ensure_data_dir():
        logger.error("Could not save ping cache: data directory not available")
        return

    cache_file = os.path.join(DATA_DIR, "ping_cache.json")

    try:
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f)
    except IOError as e:
        logger.error(f"Error saving ping cache: {e}")

def get_cached_ping_data(domain):
    """Get ping data from cache if available and not expired"""
    global PING_CACHE

    # Load cache if it's empty
    if not PING_CACHE:
        PING_CACHE = load_ping_cache()

    if domain in PING_CACHE:
        cache_entry = PING_CACHE[domain]
        cache_time = cache_entry.get('timestamp', 0)
        current_time = time.time()

        # Check if cache entry is still valid
        if current_time - cache_time < PING_CACHE_EXPIRY:
            logger.debug(f"Using cached ping data for {domain}")
            return cache_entry

    return None

def cache_ping_data(domain, ping_result):
    """Cache ping data for a domain"""
    global PING_CACHE

    # Load cache if it's empty
    if not PING_CACHE:
        PING_CACHE = load_ping_cache()

    # Add or update cache entry
    PING_CACHE[domain] = {
        'timestamp': time.time(),
        'status': ping_result['status'],
        'response_time': ping_result['response_time']
    }

    save_ping_cache(PING_CACHE)

def check_ping(domain):
    """Check if a domain is reachable via ping and return status and response time with caching"""
    # Default response for errors
    default_down_response = {
        "status": "down",
        "response_time": 0.0,
        "last_checked": datetime.now()
    }

    default_unknown_response = {
        "status": "unknown",
        "response_time": 0.0,
        "last_checked": datetime.now()
    }

    logger.debug(f"Checking ping for domain: {domain}")

    # Check if we have valid cached data
    cached_data = get_cached_ping_data(domain)
    if cached_data:
        logger.debug(f"Using cached ping data for {domain}")
        return {
            "status": cached_data['status'],
            "response_time": cached_data['response_time'],
            "last_checked": datetime.fromtimestamp(cached_data['timestamp']) if 'timestamp' in cached_data else datetime.now()
        }

    try:
        import platform
        import socket

        # First try a quick socket connection to port 80 or 443
        # This is often faster than ping and works in more environments
        try:
            # Try to resolve the domain first
            socket.gethostbyname(domain)

            # Try to connect to port 443 (HTTPS) first, then 80 (HTTP)
            for port in [443, 80]:
                try:
                    # Measure the actual response time
                    start_time = time.time()

                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)  # 1 second timeout
                    result = sock.connect_ex((domain, port))
                    sock.close()

                    end_time = time.time()

                    if result == 0:  # Connection successful
                        # Calculate actual response time in milliseconds
                        response_time = (end_time - start_time) * 1000  # Convert to ms

                        response = {
                            "status": "up",
                            "response_time": round(response_time, 2),  # Round to 2 decimal places
                            "last_checked": datetime.now()
                        }
                        cache_ping_data(domain, response)
                        # Record ping status in history
                        db.record_ping_status(domain, "up", response_time)
                        return response
                except:
                    continue
        except socket.gaierror:
            # DNS resolution failed, domain likely doesn't exist
            cache_ping_data(domain, default_down_response)
            # Record ping status in history
            db.record_ping_status(domain, "down", 0.0)
            return default_down_response

        # If socket connection failed, fall back to ping
        # Different ping command parameters for Windows vs Unix-like systems
        is_windows = platform.system().lower() == 'windows'
        param = '-n' if is_windows else '-c'
        timeout_param = '-w' if is_windows else '-W'
        timeout_value = '1000' if is_windows else '1'  # Windows uses milliseconds

        # Use a short timeout and only 1 packet with explicit timeout parameter
        command = ['ping', param, '1', timeout_param, timeout_value, domain]

        logger.debug(f"Running ping command: {' '.join(command)}")

        # Run the ping command with a timeout
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=2,  # Process timeout as a safety measure
            text=True
        )

        if result.returncode != 0:
            logger.debug(f"Ping failed for {domain} with return code {result.returncode}")
            cache_ping_data(domain, default_down_response)
            # Record ping status in history
            db.record_ping_status(domain, "down", 0.0)
            return default_down_response

        # Extract ping time from output using regex
        pattern = r'time[=<](\d+)ms' if is_windows else r'time=([\d.]+) ms'
        match = re.search(pattern, result.stdout)

        if not match:
            # If we can't extract the time but ping was successful, try to measure it ourselves
            logger.debug(f"Ping successful for {domain} but couldn't extract time from output")

            # Measure the response time manually with a second ping
            try:
                start_time = time.time()
                # Run a quick ping
                subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=2,
                    text=True
                )
                end_time = time.time()

                # Calculate response time in milliseconds
                measured_time = (end_time - start_time) * 1000

                response = {
                    "status": "up",
                    "response_time": round(measured_time, 2),
                    "last_checked": datetime.now()
                }
            except:
                # If that fails too, use a default value
                response = {
                    "status": "up",
                    "response_time": 100.0,  # Default value if we can't measure the actual time
                    "last_checked": datetime.now()
                }

            cache_ping_data(domain, response)
            # Record ping status in history
            db.record_ping_status(domain, "up", response["response_time"])
            return response

        # Return successful ping with extracted time
        response_time = float(match.group(1))
        logger.debug(f"Ping successful for {domain} with response time {response_time}ms")
        response = {
            "status": "up",
            "response_time": round(response_time, 2),  # Round to 2 decimal places
            "last_checked": datetime.now()
        }
        cache_ping_data(domain, response)
        # Record ping status in history
        db.record_ping_status(domain, "up", response_time)
        return response

    except subprocess.TimeoutExpired:
        # If the ping command times out
        logger.warning(f"Ping command timed out for {domain}")
        cache_ping_data(domain, default_down_response)
        # Record ping status in history
        db.record_ping_status(domain, "down", 0.0)
        return default_down_response
    except subprocess.SubprocessError as e:
        # Other subprocess errors
        logger.warning(f"Subprocess error in check_ping for {domain}: {str(e)}")
        cache_ping_data(domain, default_down_response)
        # Record ping status in history
        db.record_ping_status(domain, "down", 0.0)
        return default_down_response
    except Exception as e:
        # Log the specific error for debugging
        logger.error(f"Error in check_ping for {domain}: {str(e)}", exc_info=True)
        # Record ping status in history
        db.record_ping_status(domain, "unknown", None)
        return default_unknown_response

@dataclass
class Alert:
    domain: str
    type: str  # 'ssl' or 'domain'
    status: str
    message: str
    date: str

@dataclass
class EmailSettings:
    smtp_server: str
    smtp_port: int
    smtp_username: str
    smtp_password: str
    notification_email: str
    warning_threshold_days: int

@dataclass
class AppSettings:
    auto_refresh_enabled: bool
    auto_refresh_interval: int
    theme: str
    timezone: str

@dataclass
class NotificationSettings:
    """Notification settings for different platforms"""
    email: dict
    teams: dict
    slack: dict
    discord: dict

@dataclass
class Stats:
    total: int
    valid: int
    warning: int
    expired: int
    error: int

@dataclass
class PingStats:
    total: int
    up: int
    down: int
    unknown: int

import auth
import database as db
import secrets

app = Flask(__name__, static_folder='static')
app.secret_key = os.urandom(24)

# CSRF token generation
def generate_csrf_token():
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(16)
    return session['_csrf_token']

# Add CSRF token to all templates
app.jinja_env.globals['csrf_token'] = generate_csrf_token

# Add security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to each response"""
    # Content Security Policy - allow Bootstrap and other CDN resources
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https:; font-src 'self' https://cdn.jsdelivr.net; img-src 'self' data:;"
    # X-Content-Type-Options
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # X-Frame-Options
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # X-XSS-Protection
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # Referrer-Policy
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # If user is already logged in, redirect to dashboard
    if auth.get_current_user():
        return redirect(url_for('index'))

    # Clear any existing flash messages when loading the login page
    session.pop('_flashes', None)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Validate input
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')

        # Get user from database
        user = db.get_user_by_username(username)
        if not user:
            flash('Invalid username or password', 'error')
            return render_template('login.html')

        # Check if user is active
        if not user['is_active']:
            flash('Your account has been deactivated. Please contact an administrator.', 'error')
            return render_template('login.html')

        # Verify password
        password_parts = user['password_hash'].split(':')
        if len(password_parts) != 2:
            flash('Invalid account configuration. Please contact an administrator.', 'error')
            return render_template('login.html')

        stored_hash, salt = password_parts
        if not auth.verify_password(password, stored_hash, salt):
            flash('Invalid username or password', 'error')
            return render_template('login.html')

        # Create session
        session_token = auth.create_user_session(user['id'])

        # Set session cookie
        response = make_response(redirect(url_for('index')))
        response.set_cookie(
            auth.SESSION_COOKIE_NAME,
            session_token,
            max_age=auth.SESSION_EXPIRY,
            httponly=True,
            secure=request.is_secure,
            samesite='Lax'
        )

        # Check if user has any organizations
        user_orgs = db.get_user_organizations(user['id'])
        if not user_orgs and not user['is_admin']:
            # Set session cookie first, then redirect to create first organization page
            response = make_response(redirect(url_for('create_first_organization')))
            response.set_cookie(
                auth.SESSION_COOKIE_NAME,
                session_token,
                max_age=auth.SESSION_EXPIRY,
                httponly=True,
                secure=request.is_secure,
                samesite='Lax'
            )
            return response

        return response

    return render_template('login.html')

@app.route('/signup')
def signup():
    """Signup page - shows information about registration"""
    # If user is already logged in, redirect to dashboard
    if auth.get_current_user():
        return redirect(url_for('index'))

    return render_template('signup.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page - allows users to create an account"""
    # If user is already logged in, redirect to dashboard
    if auth.get_current_user():
        return redirect(url_for('index'))

    # Allow open registration for now - this can be controlled by a setting later
    # This allows users to register from the signup page

    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate input
        if not username or not email or not password or not confirm_password:
            flash('Please fill in all fields', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        # Check if username or email already exists
        if db.get_user_by_username(username):
            flash('Username already exists', 'error')
            return render_template('register.html')

        if db.get_user_by_email(email):
            flash('Email already exists', 'error')
            return render_template('register.html')

        # Hash password
        password_hash, salt = auth.hash_password(password)
        combined_hash = f"{password_hash}:{salt}"

        # Create user
        user_id = db.create_user(username, email, combined_hash)
        if not user_id:
            flash('Error creating user', 'error')
            return render_template('register.html')

        flash('Account created successfully. You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/create_first_organization', methods=['GET', 'POST'])
@auth.login_required
def create_first_organization():
    """Create first organization for new users"""
    user = auth.get_current_user()

    # Check if user already has organizations
    user_orgs = db.get_user_organizations(user['id'])
    if user_orgs:
        flash('You already have organizations', 'info')
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name', '')
        description = request.form.get('description', '')

        if not name:
            flash('Organization name is required', 'error')
            return redirect(url_for('create_first_organization'))

        # Create organization
        org_id = db.create_organization(name, description)
        if not org_id:
            flash('Failed to create organization', 'error')
            return redirect(url_for('create_first_organization'))

        # Add user to organization as admin
        db.add_user_to_organization(user['id'], org_id, 'admin')

        # Set as current organization
        session['current_organization_id'] = org_id

        flash(f'Organization "{name}" created successfully', 'success')

        # Redirect to WHOIS API key setup
        return redirect(url_for('setup_whois_api_key'))

    return render_template('create_first_organization.html', user=user)

@app.route('/setup_whois_api_key', methods=['GET', 'POST'])
@auth.login_required
def setup_whois_api_key():
    """Setup WHOIS API key after creating first organization"""
    user = auth.get_current_user()

    # Make sure user has a current organization
    if not user.get('current_organization'):
        flash('You need to create or join an organization first', 'error')
        return redirect(url_for('create_first_organization'))

    # Get the current organization ID
    org_id = user['current_organization']['id']

    if request.method == 'POST':
        api_key = request.form.get('whois_api_key', '').strip()
        skip = request.form.get('skip', 'false') == 'true'

        if skip:
            flash('You can add a WHOIS API key later in Settings', 'info')
            return redirect(url_for('index'))

        if not api_key:
            flash('Please enter a valid WHOIS API key or skip this step', 'error')
            return redirect(url_for('setup_whois_api_key'))

        # Save the WHOIS API key for this specific organization
        db.set_organization_setting(org_id, 'whois_api_key', api_key)

        flash('WHOIS API key saved successfully for your organization', 'success')
        return redirect(url_for('index'))

    return render_template('setup_whois_api_key.html', user=user)

@app.route('/logout')
def logout():
    """Logout user"""
    # Get session token from cookie
    session_token = request.cookies.get(auth.SESSION_COOKIE_NAME)
    if session_token:
        # Delete session from database
        db.delete_session(session_token)

    # Clear session cookie and all session data
    response = make_response(redirect(url_for('login')))
    response.delete_cookie(auth.SESSION_COOKIE_NAME)

    # Store flash message directly in the response
    flash('You have been logged out', 'success')

    # Clear all session data to prevent flash messages from persisting
    session.clear()

    return response

# Define data directory for persistent storage
# Use environment variable if set, otherwise use default location
DATA_DIR = os.environ.get('CERT_MONITOR_DATA_DIR', os.path.expanduser('~/.cert-monitor'))
CONFIG_FILE = os.path.join(DATA_DIR, "config.yaml")
CACHE_FILE = os.path.join(DATA_DIR, "whois_cache.json")

# Cache settings
CACHE_EXPIRY = 86400  # 24 hours in seconds

# Ensure data directory exists
def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            print(f"Created data directory at {DATA_DIR}")
        except Exception as e:
            print(f"Error creating data directory: {e}")
            # Fall back to local directory if we can't create the data directory
            return False
    return True

# Default settings are defined here for reference
DEFAULT_EMAIL_SETTINGS = {
    'smtp_server': 'smtp.office365.com',
    'smtp_port': 587,
    'smtp_username': '',
    'smtp_password': '',
    'notification_email': '',
    'warning_threshold_days': 10
}

DEFAULT_APP_SETTINGS = {
    'auto_refresh_enabled': False,
    'auto_refresh_interval': 5,
    'theme': 'light',
    'timezone': 'UTC'
}

DEFAULT_NOTIFICATIONS = {
    'email': {
        'enabled': False,
        'smtp_server': 'smtp.office365.com',
        'smtp_port': 587,
        'smtp_username': '',
        'smtp_password': '',
        'notification_email': '',
        'warning_threshold_days': 10
    },
    'teams': {
        'enabled': False,
        'webhook_url': ''
    },
    'slack': {
        'enabled': False,
        'webhook_url': '',
        'channel': ''
    },
    'discord': {
        'enabled': False,
        'webhook_url': '',
        'username': 'Certifly Bot'
    }
}

# Compatibility functions for code that still uses YAML configuration
def load_config():
    """Compatibility function that loads configuration from database"""
    # Create a config dictionary with all settings from the database
    config = {
        'ssl_domains': db.get_setting('ssl_domains', []),
        'domain_expiry': db.get_setting('domain_expiry', []),
        'ping_hosts': db.get_setting('ping_hosts', []),
        'acknowledged_alerts': db.get_setting('acknowledged_alerts', []),
        'deleted_alerts': db.get_setting('deleted_alerts', []),
        'email_settings': db.get_setting('email_settings', DEFAULT_EMAIL_SETTINGS),
        'app_settings': db.get_setting('app_settings', DEFAULT_APP_SETTINGS),
        'api_settings': db.get_setting('api_settings', {}),
        'notifications': db.get_setting('notifications', DEFAULT_NOTIFICATIONS)
    }
    return config

def save_config(data):
    """Compatibility function that saves configuration to database"""
    # Save each section of the config to the database
    if 'ssl_domains' in data:
        db.set_setting('ssl_domains', data['ssl_domains'])
    if 'domain_expiry' in data:
        db.set_setting('domain_expiry', data['domain_expiry'])
    if 'ping_hosts' in data:
        db.set_setting('ping_hosts', data['ping_hosts'])
    if 'acknowledged_alerts' in data:
        db.set_setting('acknowledged_alerts', data['acknowledged_alerts'])
    if 'deleted_alerts' in data:
        db.set_setting('deleted_alerts', data['deleted_alerts'])
    if 'email_settings' in data:
        db.set_setting('email_settings', data['email_settings'])
    if 'app_settings' in data:
        db.set_setting('app_settings', data['app_settings'])
    if 'api_settings' in data:
        db.set_setting('api_settings', data['api_settings'])
    if 'notifications' in data:
        db.set_setting('notifications', data['notifications'])

def get_email_settings() -> EmailSettings:
    """Get email settings from database"""
    settings = db.get_setting('email_settings', DEFAULT_EMAIL_SETTINGS)

    # Handle warning_threshold_days safely
    try:
        warning_threshold = int(settings.get('warning_threshold_days', 10))
    except (ValueError, TypeError):
        logger.warning(f"Invalid warning_threshold_days value: {settings.get('warning_threshold_days')}. Using default value of 10.")
        warning_threshold = 10

    # Handle smtp_port safely
    try:
        smtp_port = int(settings.get('smtp_port', 587))
    except (ValueError, TypeError):
        logger.warning(f"Invalid smtp_port value: {settings.get('smtp_port')}. Using default value of 587.")
        smtp_port = 587

    return EmailSettings(
        smtp_server=settings.get('smtp_server', 'smtp.office365.com'),
        smtp_port=smtp_port,
        smtp_username=settings.get('smtp_username', ''),
        smtp_password=settings.get('smtp_password', ''),
        notification_email=settings.get('notification_email', ''),
        warning_threshold_days=warning_threshold
    )

def get_app_settings() -> AppSettings:
    """Get app settings from database"""
    settings = db.get_setting('app_settings', DEFAULT_APP_SETTINGS)

    # Handle auto_refresh_interval safely
    try:
        auto_refresh_interval = int(settings.get('auto_refresh_interval', 5))
    except (ValueError, TypeError):
        logger.warning(f"Invalid auto_refresh_interval value: {settings.get('auto_refresh_interval')}. Using default value of 5.")
        auto_refresh_interval = 5

    return AppSettings(
        auto_refresh_enabled=settings.get('auto_refresh_enabled', False),
        auto_refresh_interval=auto_refresh_interval,
        theme=settings.get('theme', 'light'),
        timezone=settings.get('timezone', 'UTC')
    )

def get_notification_settings() -> NotificationSettings:
    """Get notification settings for all platforms from database"""
    notifications = db.get_setting('notifications', DEFAULT_NOTIFICATIONS)

    # Ensure all notification channels exist with default values
    if 'email' not in notifications:
        notifications['email'] = DEFAULT_NOTIFICATIONS['email']
    if 'teams' not in notifications:
        notifications['teams'] = DEFAULT_NOTIFICATIONS['teams']
    if 'slack' not in notifications:
        notifications['slack'] = DEFAULT_NOTIFICATIONS['slack']
    if 'discord' not in notifications:
        notifications['discord'] = DEFAULT_NOTIFICATIONS['discord']

    return NotificationSettings(
        email=notifications.get('email', {}),
        teams=notifications.get('teams', {}),
        slack=notifications.get('slack', {}),
        discord=notifications.get('discord', {})
    )

# WHOIS caching functions using database
def get_cached_whois_data(domain):
    """Get WHOIS data from cache if available and not expired"""
    cache_key = f"whois_{domain}"
    cached_data = db.get_cache(cache_key)

    if cached_data:
        logger.debug(f"Using cached WHOIS data for {domain}")
        return cached_data

    return None

def cache_whois_data(domain, data):
    """Cache WHOIS data for a domain"""
    cache_key = f"whois_{domain}"
    db.set_cache(cache_key, data, CACHE_EXPIRY)

# Email notification function removed - replaced by the notification system in notifications.py

def convert_to_user_timezone(dt, timezone_str='UTC'):
    """Convert a datetime object from UTC to the user's timezone"""
    if dt is None:
        return None

    try:
        import pytz
        # Validate the timezone
        try:
            user_tz = pytz.timezone(timezone_str)
            logger.debug(f"Using timezone: {timezone_str}")
        except pytz.exceptions.UnknownTimeZoneError:
            logger.warning(f"Unknown timezone: {timezone_str}. Using UTC instead.")
            user_tz = pytz.UTC
            timezone_str = 'UTC'

        # Ensure the datetime is timezone-aware (UTC)
        if dt.tzinfo is None:
            logger.debug(f"Making naive datetime {dt} timezone-aware (UTC)")
            dt = dt.replace(tzinfo=pytz.UTC)
        elif dt.tzinfo != pytz.UTC:
            logger.debug(f"Converting datetime {dt} with tzinfo {dt.tzinfo} to UTC")
            dt = dt.astimezone(pytz.UTC)

        # Convert to the user's timezone
        logger.debug(f"Converting datetime {dt} from UTC to {timezone_str}")
        converted_dt = dt.astimezone(user_tz)
        logger.debug(f"Converted datetime: {converted_dt}")

        return converted_dt
    except ImportError:
        # If pytz is not available, return the original datetime
        logger.warning("pytz not available, timezone conversion skipped")
        return dt
    except Exception as e:
        # If there's any error, return the original datetime
        logger.error(f"Error converting timezone: {str(e)}")
        return dt


def get_whois_api_key():
    """Get the WHOIS API key from database or environment variable"""
    # First check environment variable
    api_key = os.environ.get('WHOIS_API_KEY')
    if api_key:
        return api_key

    # Get current user and organization
    user = auth.get_current_user()
    if user and user.get('current_organization'):
        # Get organization-specific API key
        org_id = user['current_organization']['id']
        api_key = db.get_organization_setting(org_id, 'whois_api_key', '')

        if api_key:
            logger.debug(f"WHOIS API key found for organization {org_id}")
            return api_key

    # If no organization-specific key, check global settings as fallback
    api_settings = db.get_setting('api_settings', {})
    api_key = api_settings.get('whois_api_key', '')

    # Log the API key status (without revealing the actual key)
    if api_key:
        logger.debug("WHOIS API key found in global database settings")
    else:
        logger.debug("No WHOIS API key found in settings")

    return api_key

def get_whois_data(domain: str):
    """Get WHOIS data for a domain using a public API with caching"""
    # Check if we have valid cached data
    cached_data = get_cached_whois_data(domain)
    if cached_data:
        logger.debug(f"Using cached WHOIS data for {domain}")
        return cached_data

    logger.info(f"Fetching fresh WHOIS data for {domain}")

    # Get API key
    api_key = get_whois_api_key()
    if not api_key:
        # Try to get API key directly from database as a fallback
        api_settings = db.get_setting('api_settings', {})
        api_key = api_settings.get('whois_api_key', '')

        if api_key:
            logger.info("Retrieved WHOIS API key directly from database")
        else:
            logger.error("No WHOIS API key configured. Please set WHOIS_API_KEY environment variable or configure it in settings.")
            return None

    try:
        # Use WHOIS API to get domain information
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={domain}&outputFormat=json"

        # Create a request with a user agent to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        logger.debug(f"Making WHOIS API request for {domain}")

        # Use requests library for better error handling
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Raise exception for 4XX/5XX status codes

        data = response.json()
        logger.debug(f"Received WHOIS API response for {domain}")

        # Extract the relevant information
        whois_record = data.get('WhoisRecord', {})
        registrar_data = whois_record.get('registrarName', 'Unknown')

        # Try to get expiry date
        expiry_date_str = None
        registry_data = whois_record.get('registryData', {})
        if registry_data:
            expiry_date_str = registry_data.get('expiresDate')
            logger.debug(f"Found expiry date in registry data for {domain}: {expiry_date_str}")

        if not expiry_date_str and 'registryData' in whois_record:
            # Try to find expiry date in raw text
            raw_text = whois_record.get('rawText', '')
            expiry_matches = re.findall(r'Expir(?:y|ation) Date:\s*(.+)', raw_text, re.IGNORECASE)
            if expiry_matches:
                expiry_date_str = expiry_matches[0].strip()
                logger.debug(f"Found expiry date in raw text for {domain}: {expiry_date_str}")

        result = {
            'registrar': registrar_data,
            'expiry_date_str': expiry_date_str
        }

        # Cache the result
        if expiry_date_str:  # Only cache successful results
            logger.debug(f"Caching WHOIS data for {domain}")
            cache_whois_data(domain, result)
        else:
            logger.warning(f"No expiry date found for {domain}, not caching result")

        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching WHOIS data for {domain}: {str(e)}")
        return None
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Error parsing WHOIS data for {domain}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error fetching WHOIS data for {domain}: {str(e)}", exc_info=True)
        return None

# Domain expiry cache
DOMAIN_EXPIRY_CACHE = {}
DOMAIN_EXPIRY_CACHE_EXPIRY = 86400  # 24 hours in seconds (same as WHOIS cache)

def load_domain_expiry_cache():
    """Load the domain expiry cache from disk"""
    cache_file = os.path.join(DATA_DIR, "domain_expiry_cache.json")
    if not os.path.exists(cache_file):
        logger.debug("Domain expiry cache file does not exist, returning empty cache")
        return {}

    try:
        with open(cache_file, 'r') as f:
            try:
                cache_data = json.load(f)
                logger.debug(f"Loaded domain expiry cache with {len(cache_data)} entries")

                # Process each domain entry
                for domain, data in list(cache_data.items()):  # Use list() to allow modification during iteration
                    # Skip invalid entries
                    if not isinstance(data, dict):
                        logger.warning(f"Invalid cache entry for {domain}: {data}. Removing from cache.")
                        cache_data.pop(domain, None)
                        continue

                    # Validate and fix days_remaining
                    if 'days_remaining' in data:
                        try:
                            data['days_remaining'] = int(data['days_remaining'])
                        except (ValueError, TypeError):
                            logger.warning(f"Invalid days_remaining in cache for {domain}: {data['days_remaining']}. Setting to -1.")
                            data['days_remaining'] = -1
                    else:
                        logger.warning(f"Missing days_remaining in cache for {domain}. Setting to -1.")
                        data['days_remaining'] = -1

                    # Validate and fix expiry_date
                    if 'expiry_date' in data:
                        try:
                            if isinstance(data['expiry_date'], str):
                                data['expiry_date'] = datetime.fromisoformat(data['expiry_date'])
                            elif not isinstance(data['expiry_date'], datetime):
                                logger.warning(f"Invalid expiry_date type in cache for {domain}: {type(data['expiry_date'])}. Setting to current time.")
                                data['expiry_date'] = datetime.now()
                        except (ValueError, TypeError) as e:
                            logger.warning(f"Error parsing expiry_date in cache for {domain}: {e}. Setting to current time.")
                            data['expiry_date'] = datetime.now()
                    else:
                        logger.warning(f"Missing expiry_date in cache for {domain}. Setting to current time.")
                        data['expiry_date'] = datetime.now()

                    # Validate status
                    valid_statuses = ['valid', 'warning', 'expired', 'error']
                    if 'status' not in data or data['status'] not in valid_statuses:
                        logger.warning(f"Invalid status in cache for {domain}: {data.get('status')}. Setting to 'error'.")
                        data['status'] = 'error'

                    # Validate registrar
                    if 'registrar' not in data or not data['registrar']:
                        logger.warning(f"Missing registrar in cache for {domain}. Setting to 'Unknown'.")
                        data['registrar'] = 'Unknown'

                    # Validate timestamp
                    if 'timestamp' not in data or not isinstance(data['timestamp'], (int, float)):
                        logger.warning(f"Invalid timestamp in cache for {domain}: {data.get('timestamp')}. Setting to current time.")
                        data['timestamp'] = time.time()

                return cache_data
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding domain expiry cache JSON: {e}")
                return {}
    except IOError as e:
        logger.error(f"Error reading domain expiry cache file: {e}")
        return {}

def save_domain_expiry_cache(cache_data):
    """Save the domain expiry cache to disk"""
    if not cache_data:
        logger.warning("Empty cache data, not saving domain expiry cache")
        return

    if not ensure_data_dir():
        logger.error("Could not save domain expiry cache: data directory not available")
        return

    cache_file = os.path.join(DATA_DIR, "domain_expiry_cache.json")

    # Convert datetime objects to strings for JSON serialization
    serializable_cache = {}
    for domain, data in cache_data.items():
        # Skip invalid entries
        if not isinstance(data, dict):
            logger.warning(f"Invalid cache entry for {domain}: {data}. Skipping.")
            continue

        # Create a copy to avoid modifying the original
        try:
            serializable_cache[domain] = data.copy()

            # Convert expiry_date to string if it's a datetime
            if 'expiry_date' in data:
                if isinstance(data['expiry_date'], datetime):
                    serializable_cache[domain]['expiry_date'] = data['expiry_date'].isoformat()
                elif not isinstance(data['expiry_date'], str):
                    logger.warning(f"Invalid expiry_date type in cache for {domain}: {type(data['expiry_date'])}. Using current time.")
                    serializable_cache[domain]['expiry_date'] = datetime.now().isoformat()

            # Ensure days_remaining is an integer
            if 'days_remaining' in data:
                try:
                    serializable_cache[domain]['days_remaining'] = int(data['days_remaining'])
                except (ValueError, TypeError):
                    logger.warning(f"Invalid days_remaining in cache for {domain}: {data['days_remaining']}. Setting to -1.")
                    serializable_cache[domain]['days_remaining'] = -1
        except Exception as e:
            logger.error(f"Error processing cache entry for {domain}: {str(e)}")
            continue

    try:
        with open(cache_file, 'w') as f:
            json.dump(serializable_cache, f)
        logger.debug(f"Saved domain expiry cache with {len(serializable_cache)} entries")
    except IOError as e:
        logger.error(f"Error saving domain expiry cache: {e}")
    except Exception as e:
        logger.error(f"Unexpected error saving domain expiry cache: {str(e)}")

def get_cached_domain_expiry_data(domain):
    """Get domain expiry data from cache if available and not expired"""
    global DOMAIN_EXPIRY_CACHE

    # Load cache if it's empty
    if not DOMAIN_EXPIRY_CACHE:
        DOMAIN_EXPIRY_CACHE = load_domain_expiry_cache()

    if domain in DOMAIN_EXPIRY_CACHE:
        cache_entry = DOMAIN_EXPIRY_CACHE[domain]
        cache_time = cache_entry.get('timestamp', 0)
        current_time = time.time()

        # Check if cache entry is still valid
        if current_time - cache_time < DOMAIN_EXPIRY_CACHE_EXPIRY:
            logger.debug(f"Using cached domain expiry data for {domain}")
            return cache_entry

    return None

def cache_domain_expiry_data(domain, domain_status):
    """Cache domain expiry data for a domain"""
    global DOMAIN_EXPIRY_CACHE

    # Load cache if it's empty
    if not DOMAIN_EXPIRY_CACHE:
        DOMAIN_EXPIRY_CACHE = load_domain_expiry_cache()

    # Validate domain_status object
    if not domain_status:
        logger.error(f"Cannot cache domain expiry data for {domain}: domain_status is None")
        return

    # Ensure days_remaining is an integer
    try:
        days_remaining = int(domain_status.days_remaining)
    except (ValueError, TypeError):
        logger.warning(f"Invalid days_remaining for {domain}: {domain_status.days_remaining}. Using -1.")
        days_remaining = -1

    # Validate expiry_date
    if not isinstance(domain_status.expiry_date, datetime):
        logger.warning(f"Invalid expiry_date for {domain}: {domain_status.expiry_date}. Using current time.")
        expiry_date = datetime.now()
    else:
        expiry_date = domain_status.expiry_date

    # Validate registrar
    registrar = str(domain_status.registrar) if domain_status.registrar else "Unknown"

    # Validate status
    valid_statuses = ['valid', 'warning', 'expired', 'error']
    status = domain_status.status if domain_status.status in valid_statuses else 'error'

    # Add or update cache entry
    DOMAIN_EXPIRY_CACHE[domain] = {
        'timestamp': time.time(),
        'days_remaining': days_remaining,
        'expiry_date': expiry_date,
        'registrar': registrar,
        'status': status
    }

    # Save to disk
    try:
        save_domain_expiry_cache(DOMAIN_EXPIRY_CACHE)
    except Exception as e:
        logger.error(f"Error saving domain expiry cache: {str(e)}")
        # Continue even if saving fails

def check_domain_expiry(domain: str) -> DomainStatus:
    """Check domain expiry date using whois with caching"""
    logger.debug(f"Checking domain expiry for {domain}")

    # Default values for error case
    default_days_remaining = -1
    default_expiry_date = datetime.now()
    default_registrar = "Unknown"
    default_status = 'error'

    # Step 1: Try to use cached data first
    try:
        cached_data = get_cached_domain_expiry_data(domain)
        if cached_data:
            logger.debug(f"Using cached domain expiry data for {domain}")

            # Safely extract and convert days_remaining to integer
            try:
                days_remaining = int(cached_data.get('days_remaining', default_days_remaining))
            except (ValueError, TypeError):
                logger.warning(f"Invalid days_remaining in cache for {domain}: {cached_data.get('days_remaining')}. Using default.")
                days_remaining = default_days_remaining

            # Get other values with defaults
            expiry_date = cached_data.get('expiry_date', default_expiry_date)
            registrar = cached_data.get('registrar', default_registrar)
            status = cached_data.get('status', default_status)

            # Always get fresh ping status
            ping_result = check_ping(domain)

            # Return domain status from cache
            return DomainStatus(
                name=domain,
                days_remaining=days_remaining,
                expiry_date=expiry_date,
                registrar=registrar,
                status=status,
                ping_status=ping_result.get("status", "unknown")
            )
    except Exception as e:
        logger.error(f"Error using cached domain expiry data for {domain}: {str(e)}", exc_info=True)
        # Continue to fresh check

    # Step 2: Get fresh WHOIS data
    try:
        # Get WHOIS data
        whois_data = get_whois_data(domain)
        if not whois_data:
            logger.error(f"Failed to get WHOIS data for {domain}")
            raise ValueError("No WHOIS data available")

        # Check if we have an expiry date string
        expiry_date_str = whois_data.get('expiry_date_str')
        if not expiry_date_str:
            logger.error(f"No expiry date found in WHOIS data for {domain}")
            raise ValueError("No expiry date in WHOIS data")

        # Try to parse the expiry date
        expiry_date = None
        date_formats = [
            '%Y-%m-%dT%H:%M:%SZ',      # ISO format
            '%Y-%m-%dT%H:%M:%S.%fZ',   # ISO format with microseconds
            '%Y-%m-%dT%H:%M:%S%z',     # ISO format with timezone
            '%Y-%m-%d',                # Simple date
            '%d-%b-%Y',                # 01-Jan-2023
            '%d %b %Y',                # 01 Jan 2023
            '%Y.%m.%d',                # 2023.01.01
            '%d.%m.%Y',                # 01.01.2023
            '%Y/%m/%d',                # 2023/01/01
            '%d/%m/%Y',                # 01/01/2023
            '%b %d %Y',                # Jan 01 2023
            '%B %d %Y',                # January 01 2023
            '%d-%B-%Y',                # 01-January-2023
            '%Y-%m-%d %H:%M:%S',       # 2023-01-01 12:00:00
        ]

        logger.debug(f"Trying to parse expiry date string for {domain}: '{expiry_date_str}'")

        for date_format in date_formats:
            try:
                expiry_date = datetime.strptime(expiry_date_str, date_format)
                logger.debug(f"Successfully parsed expiry date for {domain} using format {date_format}: {expiry_date}")
                break
            except ValueError:
                continue

        if not expiry_date:
            logger.error(f"Could not parse expiry date string for {domain}: '{expiry_date_str}'")
            raise ValueError(f"Could not parse expiry date: {expiry_date_str}")

        # Calculate days remaining
        days_remaining = (expiry_date - datetime.now()).days

        # Ensure days_remaining is an integer
        days_remaining = int(days_remaining)

        # Get registrar info
        registrar = whois_data.get('registrar', default_registrar)

        # Get warning threshold from settings
        settings = get_email_settings()
        try:
            warning_threshold = int(settings.warning_threshold_days)
        except (ValueError, TypeError):
            logger.warning(f"Invalid warning_threshold_days: {settings.warning_threshold_days}. Using default value of 10.")
            warning_threshold = 10

        # Determine status
        if days_remaining <= 0:
            status = 'expired'
            logger.warning(f"Domain {domain} has expired")
        elif days_remaining <= warning_threshold:
            status = 'warning'
            logger.warning(f"Domain {domain} will expire in {days_remaining} days")
        else:
            status = 'valid'

        # Get ping status
        ping_result = check_ping(domain)

        # Create domain status object
        domain_status = DomainStatus(
            name=domain,
            days_remaining=days_remaining,
            expiry_date=expiry_date,
            registrar=registrar,
            status=status,
            ping_status=ping_result.get("status", "unknown")
        )

        # Cache the successful result
        try:
            cache_domain_expiry_data(domain, domain_status)
        except Exception as cache_error:
            logger.error(f"Error caching domain expiry data for {domain}: {str(cache_error)}")
            # Continue even if caching fails

        # Send notifications if domain is in warning or expired state
        if status in ['warning', 'expired']:
            try:
                notification_settings = get_notification_settings()

                # Send notifications to all enabled platforms
                if notification_settings.email.get('enabled', False):
                    send_domain_expiry_notification('email', notification_settings.email, domain_status)

                if notification_settings.teams.get('enabled', False):
                    send_domain_expiry_notification('teams', notification_settings.teams, domain_status)

                if notification_settings.slack.get('enabled', False):
                    send_domain_expiry_notification('slack', notification_settings.slack, domain_status)

                if notification_settings.discord.get('enabled', False):
                    send_domain_expiry_notification('discord', notification_settings.discord, domain_status)
            except Exception as notify_error:
                logger.error(f"Error sending notifications for {domain}: {str(notify_error)}")
                # Continue even if notification fails

        return domain_status

    except Exception as e:
        # Handle any errors in the WHOIS data processing
        logger.error(f"Error checking domain expiry for {domain}: {str(e)}", exc_info=True)

        # Get ping status if possible
        try:
            ping_result = check_ping(domain)
            ping_status = ping_result.get("status", "unknown")
        except Exception:
            ping_status = "unknown"

        # Create error status
        error_status = DomainStatus(
            name=domain,
            days_remaining=default_days_remaining,
            expiry_date=default_expiry_date,
            registrar=f"{default_registrar} (Error: {str(e)[:50]}...)" if len(str(e)) > 50 else f"{default_registrar} (Error: {str(e)})",
            status=default_status,
            ping_status=ping_status
        )

        # Cache the error result with a shorter expiry time (1 hour)
        try:
            DOMAIN_EXPIRY_CACHE[domain] = {
                'timestamp': time.time() - DOMAIN_EXPIRY_CACHE_EXPIRY + 3600,  # Expire in 1 hour
                'days_remaining': default_days_remaining,
                'expiry_date': default_expiry_date,
                'registrar': f"{default_registrar} (Error retrieving data)",
                'status': default_status
            }
            save_domain_expiry_cache(DOMAIN_EXPIRY_CACHE)
        except Exception as cache_error:
            logger.error(f"Error caching error status for {domain}: {str(cache_error)}")
            # Continue even if caching fails

        return error_status



# SSL Certificate cache
SSL_CACHE = {}
SSL_CACHE_EXPIRY = 3600  # 1 hour in seconds

def load_ssl_cache():
    """Load the SSL certificate cache from disk"""
    cache_file = os.path.join(DATA_DIR, "ssl_cache.json")
    if not os.path.exists(cache_file):
        return {}

    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
            # Convert string dates back to datetime objects
            for domain, data in cache_data.items():
                if 'expiry_date' in data:
                    try:
                        data['expiry_date'] = datetime.fromisoformat(data['expiry_date'])
                    except ValueError:
                        # If date can't be parsed, consider the cache entry invalid
                        data['timestamp'] = 0
            return cache_data
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Error loading SSL cache: {e}")
        return {}

def save_ssl_cache(cache_data):
    """Save the SSL certificate cache to disk"""
    if not ensure_data_dir():
        logger.error("Could not save SSL cache: data directory not available")
        return

    cache_file = os.path.join(DATA_DIR, "ssl_cache.json")

    # Convert datetime objects to strings for JSON serialization
    serializable_cache = {}
    for domain, data in cache_data.items():
        serializable_cache[domain] = data.copy()
        if 'expiry_date' in data and isinstance(data['expiry_date'], datetime):
            serializable_cache[domain]['expiry_date'] = data['expiry_date'].isoformat()

    try:
        with open(cache_file, 'w') as f:
            json.dump(serializable_cache, f)
    except IOError as e:
        logger.error(f"Error saving SSL cache: {e}")

def get_cached_ssl_data(domain):
    """Get SSL certificate data from cache if available and not expired"""
    global SSL_CACHE

    # Load cache if it's empty
    if not SSL_CACHE:
        SSL_CACHE = load_ssl_cache()

    if domain in SSL_CACHE:
        cache_entry = SSL_CACHE[domain]
        cache_time = cache_entry.get('timestamp', 0)
        current_time = time.time()

        # Check if cache entry is still valid
        if current_time - cache_time < SSL_CACHE_EXPIRY:
            logger.debug(f"Using cached SSL data for {domain}")
            return cache_entry

    return None

def cache_ssl_data(domain, cert_status):
    """Cache SSL certificate data for a domain"""
    global SSL_CACHE

    # Load cache if it's empty
    if not SSL_CACHE:
        SSL_CACHE = load_ssl_cache()

    # Add or update cache entry
    SSL_CACHE[domain] = {
        'timestamp': time.time(),
        'days_remaining': cert_status.days_remaining,
        'expiry_date': cert_status.expiry_date,
        'status': cert_status.status
    }

    save_ssl_cache(SSL_CACHE)

def check_certificate(domain: str) -> CertificateStatus:
    """Check SSL certificate expiry date using Python's ssl module with caching"""
    logger.debug(f"Checking SSL certificate for {domain}")

    # Check if we have valid cached data
    cached_data = get_cached_ssl_data(domain)
    if cached_data:
        logger.debug(f"Using cached SSL data for {domain}")

        # Check ping status (always fresh)
        ping_result = check_ping(domain)

        return CertificateStatus(
            domain=domain,
            days_remaining=cached_data['days_remaining'],
            expiry_date=cached_data['expiry_date'],
            status=cached_data['status'],
            ping_status=ping_result["status"]
        )

    try:
        import ssl
        import socket
        from datetime import datetime

        # Create a context with default verification options
        context = ssl.create_default_context()

        logger.debug(f"Connecting to {domain}:443")

        # Connect to the server with a shorter timeout
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate
                cert = ssock.getpeercert()

                # Extract expiry date
                expiry_date_tuple = cert['notAfter']
                # Format: 'May 30 00:00:00 2023 GMT'
                expiry_date = datetime.strptime(expiry_date_tuple, '%b %d %H:%M:%S %Y %Z')
                days_remaining = (expiry_date - datetime.now()).days

                logger.debug(f"Certificate for {domain} expires on {expiry_date}, {days_remaining} days remaining")

                # Get settings with safe warning threshold
                settings = get_email_settings()

                # Ensure warning_threshold_days is an integer
                try:
                    warning_threshold = int(settings.warning_threshold_days)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid warning_threshold_days: {settings.warning_threshold_days}. Using default value of 10.")
                    warning_threshold = 10

                status = 'valid'
                if days_remaining <= 0:
                    status = 'expired'
                    logger.warning(f"Certificate for {domain} has expired")
                elif days_remaining <= warning_threshold:
                    status = 'warning'
                    logger.warning(f"Certificate for {domain} will expire in {days_remaining} days")

                # Check ping status
                ping_result = check_ping(domain)

                cert_status = CertificateStatus(
                    domain=domain,
                    days_remaining=days_remaining,
                    expiry_date=expiry_date,
                    status=status,
                    ping_status=ping_result["status"]
                )

                # Cache the successful result
                cache_ssl_data(domain, cert_status)

                # Send notifications if certificate is in warning or expired state
                if status in ['warning', 'expired']:
                    # Get notification settings
                    notification_settings = get_notification_settings()
                    logger.info(f"Sending notifications for {domain} certificate ({status})")

                    # Send notifications to all enabled platforms
                    if notification_settings.email.get('enabled', False):
                        logger.debug(f"Sending email notification for {domain}")
                        send_certificate_expiry_notification('email', notification_settings.email, cert_status)

                    if notification_settings.teams.get('enabled', False):
                        logger.debug(f"Sending Teams notification for {domain}")
                        send_certificate_expiry_notification('teams', notification_settings.teams, cert_status)

                    if notification_settings.slack.get('enabled', False):
                        logger.debug(f"Sending Slack notification for {domain}")
                        send_certificate_expiry_notification('slack', notification_settings.slack, cert_status)

                    if notification_settings.discord.get('enabled', False):
                        logger.debug(f"Sending Discord notification for {domain}")
                        send_certificate_expiry_notification('discord', notification_settings.discord, cert_status)

                return cert_status
    except ssl.SSLError as e:
        logger.error(f"SSL Error checking certificate for {domain}: {str(e)}")
        ping_result = check_ping(domain)
        return CertificateStatus(
            domain=domain,
            days_remaining=-1,
            expiry_date=datetime.now(),
            status='error',
            ping_status=ping_result["status"]
        )
    except socket.gaierror as e:
        logger.error(f"DNS resolution error for {domain}: {str(e)}")
        ping_result = check_ping(domain)
        return CertificateStatus(
            domain=domain,
            days_remaining=-1,
            expiry_date=datetime.now(),
            status='error',
            ping_status=ping_result["status"]
        )
    except socket.timeout as e:
        logger.error(f"Connection timeout for {domain}: {str(e)}")
        ping_result = check_ping(domain)
        return CertificateStatus(
            domain=domain,
            days_remaining=-1,
            expiry_date=datetime.now(),
            status='error',
            ping_status=ping_result["status"]
        )
    except Exception as e:
        logger.error(f"Error checking certificate for {domain}: {str(e)}", exc_info=True)
        # Even if certificate check fails, try to ping the domain
        ping_result = check_ping(domain)

        return CertificateStatus(
            domain=domain,
            days_remaining=-1,
            expiry_date=datetime.now(),
            status='error',
            ping_status=ping_result["status"]
        )

def clean_domain_name(domain):
    """Clean a domain name by removing protocol, trailing slashes, and paths"""
    if not domain:
        return ""

    # Clean the domain (remove http://, https://, trailing slashes)
    domain = domain.lower().strip()
    if domain.startswith('http://'):
        domain = domain[7:]
    elif domain.startswith('https://'):
        domain = domain[8:]

    # Remove any path after domain
    domain = domain.split('/')[0]

    return domain

def is_valid_domain(domain):
    """Check if a domain name is valid"""
    if not domain:
        return False

    # Clean the domain first
    domain = clean_domain_name(domain)

    # Simple regex for domain validation
    pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    # Allow IP addresses as well
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

    return bool(re.match(pattern, domain) or re.match(ip_pattern, domain))

def get_ssl_stats(certificates):
    """Calculate SSL certificate statistics"""
    total = len(certificates)
    valid = sum(1 for cert in certificates if cert.status == 'valid')
    warning = sum(1 for cert in certificates if cert.status == 'warning')
    expired = sum(1 for cert in certificates if cert.status == 'expired')
    error = sum(1 for cert in certificates if cert.status == 'error')

    return Stats(
        total=total,
        valid=valid,
        warning=warning,
        expired=expired,
        error=error
    )

def get_domain_stats(domains):
    """Calculate domain expiry statistics"""
    total = len(domains)
    valid = sum(1 for domain in domains if domain.status == 'valid')
    warning = sum(1 for domain in domains if domain.status == 'warning')
    expired = sum(1 for domain in domains if domain.status == 'expired')
    error = sum(1 for domain in domains if domain.status == 'error')

    return Stats(
        total=total,
        valid=valid,
        warning=warning,
        expired=expired,
        error=error
    )

def get_ping_hosts():
    """Get all ping hosts from config"""
    config = load_config()
    return config.get('ping_hosts', [])

def check_ping_hosts():
    """Check all ping hosts and return their status"""
    hosts = get_ping_hosts()
    results = []

    for host_entry in hosts:
        host = host_entry.get('host', '')
        if not host:
            continue

        ping_result = check_ping(host)

        # Get response history from config
        response_history = host_entry.get('response_history', [])

        # Add current response time to history if up
        if ping_result["status"] == "up":
            if 'response_history' not in host_entry:
                host_entry['response_history'] = []

            host_entry['response_history'].append(ping_result["response_time"])
            # Keep only the last 20 entries
            host_entry['response_history'] = host_entry['response_history'][-20:]
            response_history = host_entry['response_history']

        results.append(PingStatus(
            host=host,
            status=ping_result["status"],
            last_checked=datetime.now(),
            response_time=ping_result["response_time"],
            response_history=response_history
        ))

    return results

def get_ping_stats(ping_results):
    """Calculate ping statistics"""
    total = len(ping_results)
    up = sum(1 for result in ping_results if result['status'] == 'up')
    down = sum(1 for result in ping_results if result['status'] == 'down')
    unknown = sum(1 for result in ping_results if result['status'] == 'unknown')

    return PingStats(
        total=total,
        up=up,
        down=down,
        unknown=unknown
    )

def get_recent_alerts(certificates, domains, limit=5):
    """Get recent alerts from both SSL certificates and domain expiry"""
    alerts = []

    # Add SSL certificate alerts
    for cert in certificates:
        if cert.status in ['warning', 'expired', 'error']:
            message = ""
            if cert.status == 'warning':
                message = f"Certificate will expire in {cert.days_remaining} days"
            elif cert.status == 'expired':
                message = "Certificate has expired"
            else:
                message = "Error checking certificate"

            alerts.append(Alert(
                domain=cert.domain,
                type='ssl',
                status=cert.status,
                message=message,
                date=datetime.now().strftime('%Y-%m-%d')
            ))

    # Add domain expiry alerts
    for domain in domains:
        if domain.status in ['warning', 'expired', 'error']:
            message = ""
            if domain.status == 'warning':
                message = f"Domain will expire in {domain.days_remaining} days"
            elif domain.status == 'expired':
                message = "Domain has expired"
            else:
                message = "Error checking domain"

            alerts.append(Alert(
                domain=domain.name,
                type='domain',
                status=domain.status,
                message=message,
                date=datetime.now().strftime('%Y-%m-%d')
            ))

    # Sort by status severity (expired, warning, error) and limit
    status_priority = {'expired': 0, 'warning': 1, 'error': 2}
    alerts.sort(key=lambda x: status_priority.get(x.status, 3))

    return alerts[:limit]

def generate_alert_id(alert_type, domain, status):
    """Generate a unique ID for an alert based on its properties"""
    return f"{alert_type.lower()}:{domain}:{status.lower()}"

@app.route('/alerts')
@auth.login_required
def alerts():
    """Alerts page showing all system alerts"""
    start_time = time.time()
    logger.debug("Starting alerts page load")

    # Get current user and organization
    user = auth.get_current_user()
    current_org = user.get('current_organization')

    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get all alerts from the system
    alerts = []

    # Get SSL certificate alerts
    config = load_config()
    acknowledged_alerts = config.get('acknowledged_alerts', [])
    deleted_alerts = config.get('deleted_alerts', [])
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M')

    # Get domains from database for current organization only
    domains_from_db = db.get_domains_by_organization(current_org['id'])

    # Process each domain
    for domain in domains_from_db:
        domain_name = domain['name']
        # Check if domain is monitored for SSL
        if domain['ssl_monitored']:
            cert_status = check_certificate(domain_name)

            if cert_status.status == 'warning':
                alert_id = generate_alert_id('SSL', domain_name, 'warning')
                # Skip if this alert has been deleted
                if alert_id in deleted_alerts:
                    continue
                is_acknowledged = alert_id in acknowledged_alerts
                alerts.append({
                    'id': alert_id,
                    'type': 'SSL',
                    'icon': 'shield-exclamation',
                    'message': f'SSL certificate for {domain_name} will expire in {cert_status.days_remaining} days',
                    'time': current_time,
                    'domain': domain_name,
                    'acknowledged': is_acknowledged
                })
            elif cert_status.status == 'expired':
                alert_id = generate_alert_id('SSL', domain_name, 'expired')
                # Skip if this alert has been deleted
                if alert_id in deleted_alerts:
                    continue
                is_acknowledged = alert_id in acknowledged_alerts
                alerts.append({
                    'id': alert_id,
                    'type': 'SSL',
                    'icon': 'shield-x',
                    'message': f'SSL certificate for {domain_name} has expired',
                    'time': current_time,
                    'domain': domain_name,
                    'acknowledged': is_acknowledged
                })
            elif cert_status.status == 'error':
                alert_id = generate_alert_id('SSL', domain_name, 'error')
                # Skip if this alert has been deleted
                if alert_id in deleted_alerts:
                    continue
                is_acknowledged = alert_id in acknowledged_alerts
                alerts.append({
                    'id': alert_id,
                    'type': 'Error',
                    'icon': 'exclamation-triangle',
                    'message': f'Error checking SSL certificate for {domain_name}',
                    'time': current_time,
                    'domain': domain_name,
                    'acknowledged': is_acknowledged
                })

        # Check if domain is monitored for expiry
        if domain['expiry_monitored']:
            domain_status = check_domain_expiry(domain_name)

            if domain_status.status == 'warning':
                alert_id = generate_alert_id('Domain', domain_name, 'warning')
                # Skip if this alert has been deleted
                if alert_id in deleted_alerts:
                    continue
                is_acknowledged = alert_id in acknowledged_alerts
                alerts.append({
                    'id': alert_id,
                    'type': 'Domain',
                    'icon': 'calendar-exclamation',
                    'message': f'Domain {domain_name} will expire in {domain_status.days_remaining} days',
                    'time': current_time,
                    'domain': domain_name,
                    'acknowledged': is_acknowledged
                })
            elif domain_status.status == 'expired':
                alert_id = generate_alert_id('Domain', domain_name, 'expired')
                # Skip if this alert has been deleted
                if alert_id in deleted_alerts:
                    continue
                is_acknowledged = alert_id in acknowledged_alerts
                alerts.append({
                    'id': alert_id,
                    'type': 'Domain',
                    'icon': 'calendar-x',
                    'message': f'Domain {domain_name} has expired',
                    'time': current_time,
                    'domain': domain_name,
                    'acknowledged': is_acknowledged
                })
            elif domain_status.status == 'error':
                alert_id = generate_alert_id('Domain', domain_name, 'error')
                # Skip if this alert has been deleted
                if alert_id in deleted_alerts:
                    continue
                is_acknowledged = alert_id in acknowledged_alerts
                alerts.append({
                    'id': alert_id,
                    'type': 'Error',
                    'icon': 'exclamation-triangle',
                    'message': f'Error checking expiry for domain {domain_name}',
                    'time': current_time,
                    'domain': domain_name,
                    'acknowledged': is_acknowledged
                })

        # Check if domain is monitored for ping
        if domain['ping_monitored']:
            # If we already checked this domain for SSL or expiry, we already have ping status
            # Otherwise, do a separate ping check
            ping_status = None

            # Try to find existing ping status from previous checks
            for alert in alerts:
                if alert['domain'] == domain_name and 'ping_status' in alert:
                    ping_status = alert['ping_status']
                    break

            if ping_status is None:
                ping_result = check_ping(domain_name)
                ping_status = ping_result['status']

            if ping_status == 'down':
                alert_id = generate_alert_id('Ping', domain_name, 'down')
                # Skip if this alert has been deleted
                if alert_id in deleted_alerts:
                    continue
                is_acknowledged = alert_id in acknowledged_alerts
                alerts.append({
                    'id': alert_id,
                    'type': 'Ping',
                    'icon': 'wifi-off',
                    'message': f'Host {domain_name} is down',
                    'time': current_time,
                    'domain': domain_name,
                    'acknowledged': is_acknowledged
                })

    # Sort alerts by acknowledgment status (unacknowledged first) and then by time (newest first)
    alerts.sort(key=lambda x: (x['acknowledged'], x['time']), reverse=True)

    end_time = time.time()
    logger.debug(f"Alerts page loaded in {end_time - start_time:.2f} seconds")

    return render_template('alerts.html', alerts=alerts)

@app.route('/acknowledge_alert/<alert_id>', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    config = load_config()

    if 'acknowledged_alerts' not in config:
        config['acknowledged_alerts'] = []

    if alert_id not in config['acknowledged_alerts']:
        # Get alert details before acknowledging
        alert_details = None

        # Get SSL certificate alerts
        for entry in config.get('ssl_domains', []):
            domain_name = entry.get('url')
            cert_status = check_certificate(domain_name)

            if cert_status.status in ['warning', 'expired', 'error']:
                temp_alert_id = generate_alert_id('SSL', domain_name, cert_status.status)
                if temp_alert_id == alert_id:
                    alert_details = {
                        'id': alert_id,
                        'type': 'SSL',
                        'domain': domain_name,
                        'status': cert_status.status,
                        'message': f'SSL certificate for {domain_name} will expire in {cert_status.days_remaining} days' if cert_status.status == 'warning' else
                                  f'SSL certificate for {domain_name} has expired' if cert_status.status == 'expired' else
                                  f'Error checking SSL certificate for {domain_name}'
                    }
                    break

        # If not found, check domain expiry alerts
        if not alert_details:
            for entry in config.get('domain_expiry', []):
                domain_name = entry.get('name')
                domain_status = check_domain_expiry(domain_name)

                if domain_status.status in ['warning', 'expired', 'error']:
                    temp_alert_id = generate_alert_id('Domain', domain_name, domain_status.status)
                    if temp_alert_id == alert_id:
                        alert_details = {
                            'id': alert_id,
                            'type': 'Domain',
                            'domain': domain_name,
                            'status': domain_status.status,
                            'message': f'Domain {domain_name} will expire in {domain_status.days_remaining} days' if domain_status.status == 'warning' else
                                      f'Domain {domain_name} has expired' if domain_status.status == 'expired' else
                                      f'Error checking expiry for domain {domain_name}'
                        }
                        break

        # If still not found, check ping alerts
        if not alert_details:
            for entry in config.get('ping_hosts', []):
                domain_name = entry.get('host')
                ping_result = check_ping(domain_name)

                if ping_result['status'] == 'down':
                    temp_alert_id = generate_alert_id('Ping', domain_name, 'down')
                    if temp_alert_id == alert_id:
                        alert_details = {
                            'id': alert_id,
                            'type': 'Ping',
                            'domain': domain_name,
                            'status': ping_result['status'],
                            'message': f'Host {domain_name} is down'
                        }
                        break

        if alert_details:
            config['acknowledged_alerts'].append(alert_id)
            save_config(config)
            flash(f"Alert '{alert_details['message']}' acknowledged", 'success')
        else:
            flash("Alert not found", 'error')

    return redirect(url_for('alerts'))

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy'}), 200
                    temp_alert_id = generate_alert_id('Ping', domain_name, 'down')
                    if temp_alert_id == alert_id:
                        alert_details = {
                            'id': alert_id,
                            'type': 'Ping',
                            'domain': domain_name,
                            'status': 'down',
                            'message': f'Host {domain_name} is down'
                        }
                        break

        # Add to acknowledged alerts
        config['acknowledged_alerts'].append(alert_id)
        save_config(config)

        # Record in alert history
        if alert_details:
            import database as db
            current_user = auth.get_current_user()
            user_id = current_user['id'] if current_user else None
            username = current_user['username'] if current_user else 'System'

            db.add_alert_history(
                alert_id=alert_id,
                domain_name=alert_details['domain'],
                alert_type=alert_details['type'].lower(),
                status=alert_details.get('status', 'warning'),
                message=alert_details['message'],
                action='acknowledged',
                user_id=user_id,
                username=username
            )

        flash('Alert acknowledged successfully', 'success')
    else:
        flash('Alert already acknowledged', 'info')

    return redirect(url_for('alerts'))

@app.route('/unacknowledge_alert/<alert_id>', methods=['POST'])
def unacknowledge_alert(alert_id):
    """Remove acknowledgment from an alert"""
    config = load_config()

    if 'acknowledged_alerts' in config and alert_id in config['acknowledged_alerts']:
        # Get alert details before unacknowledging
        alert_details = None

        # Get SSL certificate alerts
        for entry in config.get('ssl_domains', []):
            domain_name = entry.get('url')
            cert_status = check_certificate(domain_name)

            if cert_status.status in ['warning', 'expired', 'error']:
                temp_alert_id = generate_alert_id('SSL', domain_name, cert_status.status)
                if temp_alert_id == alert_id:
                    alert_details = {
                        'id': alert_id,
                        'type': 'SSL',
                        'domain': domain_name,
                        'status': cert_status.status,
                        'message': f'SSL certificate for {domain_name} will expire in {cert_status.days_remaining} days' if cert_status.status == 'warning' else
                                  f'SSL certificate for {domain_name} has expired' if cert_status.status == 'expired' else
                                  f'Error checking SSL certificate for {domain_name}'
                    }
                    break

        # If not found, check domain expiry alerts
        if not alert_details:
            for entry in config.get('domain_expiry', []):
                domain_name = entry.get('name')
                domain_status = check_domain_expiry(domain_name)

                if domain_status.status in ['warning', 'expired', 'error']:
                    temp_alert_id = generate_alert_id('Domain', domain_name, domain_status.status)
                    if temp_alert_id == alert_id:
                        alert_details = {
                            'id': alert_id,
                            'type': 'Domain',
                            'domain': domain_name,
                            'status': domain_status.status,
                            'message': f'Domain {domain_name} will expire in {domain_status.days_remaining} days' if domain_status.status == 'warning' else
                                      f'Domain {domain_name} has expired' if domain_status.status == 'expired' else
                                      f'Error checking expiry for domain {domain_name}'
                        }
                        break

        # If still not found, check ping alerts
        if not alert_details:
            for entry in config.get('ping_hosts', []):
                domain_name = entry.get('host')
                ping_result = check_ping(domain_name)

                if ping_result['status'] == 'down':
                    temp_alert_id = generate_alert_id('Ping', domain_name, 'down')
                    if temp_alert_id == alert_id:
                        alert_details = {
                            'id': alert_id,
                            'type': 'Ping',
                            'domain': domain_name,
                            'status': 'down',
                            'message': f'Host {domain_name} is down'
                        }
                        break

        # Remove from acknowledged alerts
        config['acknowledged_alerts'].remove(alert_id)
        save_config(config)

        # Record in alert history
        if alert_details:
            import database as db
            current_user = auth.get_current_user()
            user_id = current_user['id'] if current_user else None
            username = current_user['username'] if current_user else 'System'

            db.add_alert_history(
                alert_id=alert_id,
                domain_name=alert_details['domain'],
                alert_type=alert_details['type'].lower(),
                status=alert_details.get('status', 'warning'),
                message=alert_details['message'],
                action='unacknowledged',
                user_id=user_id,
                username=username
            )

        flash('Alert acknowledgment removed', 'success')
    else:
        flash('Alert was not acknowledged', 'info')

    return redirect(url_for('alerts'))

@app.route('/delete_alert/<alert_id>', methods=['POST'])
def delete_alert(alert_id):
    """Delete an acknowledged alert"""
    config = load_config()

    # Only allow deletion of acknowledged alerts
    if 'acknowledged_alerts' in config and alert_id in config['acknowledged_alerts']:
        # Get alert details before deleting
        alert_details = None

        # Get SSL certificate alerts
        for entry in config.get('ssl_domains', []):
            domain_name = entry.get('url')
            cert_status = check_certificate(domain_name)

            if cert_status.status in ['warning', 'expired', 'error']:
                temp_alert_id = generate_alert_id('SSL', domain_name, cert_status.status)
                if temp_alert_id == alert_id:
                    alert_details = {
                        'id': alert_id,
                        'type': 'SSL',
                        'domain': domain_name,
                        'status': cert_status.status,
                        'message': f'SSL certificate for {domain_name} will expire in {cert_status.days_remaining} days' if cert_status.status == 'warning' else
                                  f'SSL certificate for {domain_name} has expired' if cert_status.status == 'expired' else
                                  f'Error checking SSL certificate for {domain_name}'
                    }
                    break

        # If not found, check domain expiry alerts
        if not alert_details:
            for entry in config.get('domain_expiry', []):
                domain_name = entry.get('name')
                domain_status = check_domain_expiry(domain_name)

                if domain_status.status in ['warning', 'expired', 'error']:
                    temp_alert_id = generate_alert_id('Domain', domain_name, domain_status.status)
                    if temp_alert_id == alert_id:
                        alert_details = {
                            'id': alert_id,
                            'type': 'Domain',
                            'domain': domain_name,
                            'status': domain_status.status,
                            'message': f'Domain {domain_name} will expire in {domain_status.days_remaining} days' if domain_status.status == 'warning' else
                                      f'Domain {domain_name} has expired' if domain_status.status == 'expired' else
                                      f'Error checking expiry for domain {domain_name}'
                        }
                        break

        # If still not found, check ping alerts
        if not alert_details:
            for entry in config.get('ping_hosts', []):
                domain_name = entry.get('host')
                ping_result = check_ping(domain_name)

                if ping_result['status'] == 'down':
                    temp_alert_id = generate_alert_id('Ping', domain_name, 'down')
                    if temp_alert_id == alert_id:
                        alert_details = {
                            'id': alert_id,
                            'type': 'Ping',
                            'domain': domain_name,
                            'status': 'down',
                            'message': f'Host {domain_name} is down'
                        }
                        break

        # Remove from acknowledged alerts
        config['acknowledged_alerts'].remove(alert_id)

        # Add to deleted alerts list
        if 'deleted_alerts' not in config:
            config['deleted_alerts'] = []

        if alert_id not in config['deleted_alerts']:
            config['deleted_alerts'].append(alert_id)

        save_config(config)

        # Record in alert history
        if alert_details:
            import database as db
            current_user = auth.get_current_user()
            user_id = current_user['id'] if current_user else None
            username = current_user['username'] if current_user else 'System'

            db.add_alert_history(
                alert_id=alert_id,
                domain_name=alert_details['domain'],
                alert_type=alert_details['type'].lower(),
                status=alert_details.get('status', 'warning'),
                message=alert_details['message'],
                action='deleted',
                user_id=user_id,
                username=username
            )

        flash('Alert deleted successfully', 'success')
    else:
        flash('Only acknowledged alerts can be deleted', 'warning')

    return redirect(url_for('alerts'))

@app.route('/acknowledge_all_alerts', methods=['POST'])
def acknowledge_all_alerts():
    """Acknowledge multiple alerts at once"""
    alert_ids = request.form.getlist('alert_ids')

    if not alert_ids:
        flash('No alerts selected', 'warning')
        return redirect(url_for('alerts'))

    config = load_config()

    if 'acknowledged_alerts' not in config:
        config['acknowledged_alerts'] = []

    # Add all alert IDs that aren't already acknowledged
    added_count = 0
    for alert_id in alert_ids:
        if alert_id not in config['acknowledged_alerts']:
            config['acknowledged_alerts'].append(alert_id)
            added_count += 1

    if added_count > 0:
        save_config(config)
        flash(f'Acknowledged {added_count} alerts', 'success')
    else:
        flash('All selected alerts were already acknowledged', 'info')

    return redirect(url_for('alerts'))

@app.route('/delete_all_acknowledged_alerts', methods=['POST'])
def delete_all_acknowledged_alerts():
    """Delete all acknowledged alerts"""
    config = load_config()

    if 'acknowledged_alerts' not in config or not config['acknowledged_alerts']:
        flash('No acknowledged alerts to delete', 'info')
        return redirect(url_for('alerts'))

    # Count the number of alerts being deleted
    deleted_count = len(config['acknowledged_alerts'])

    # Ensure deleted_alerts list exists
    if 'deleted_alerts' not in config:
        config['deleted_alerts'] = []

    # Get alert details for all acknowledged alerts
    alert_details_map = {}

    # Check SSL certificate alerts
    for entry in config.get('ssl_domains', []):
        domain_name = entry.get('url')
        cert_status = check_certificate(domain_name)

        if cert_status.status in ['warning', 'expired', 'error']:
            alert_id = generate_alert_id('SSL', domain_name, cert_status.status)
            if alert_id in config['acknowledged_alerts']:
                alert_details_map[alert_id] = {
                    'id': alert_id,
                    'type': 'SSL',
                    'domain': domain_name,
                    'status': cert_status.status,
                    'message': f'SSL certificate for {domain_name} will expire in {cert_status.days_remaining} days' if cert_status.status == 'warning' else
                              f'SSL certificate for {domain_name} has expired' if cert_status.status == 'expired' else
                              f'Error checking SSL certificate for {domain_name}'
                }

    # Check domain expiry alerts
    for entry in config.get('domain_expiry', []):
        domain_name = entry.get('name')
        domain_status = check_domain_expiry(domain_name)

        if domain_status.status in ['warning', 'expired', 'error']:
            alert_id = generate_alert_id('Domain', domain_name, domain_status.status)
            if alert_id in config['acknowledged_alerts']:
                alert_details_map[alert_id] = {
                    'id': alert_id,
                    'type': 'Domain',
                    'domain': domain_name,
                    'status': domain_status.status,
                    'message': f'Domain {domain_name} will expire in {domain_status.days_remaining} days' if domain_status.status == 'warning' else
                              f'Domain {domain_name} has expired' if domain_status.status == 'expired' else
                              f'Error checking expiry for domain {domain_name}'
                }

    # Check ping alerts
    for entry in config.get('ping_hosts', []):
        domain_name = entry.get('host')
        ping_result = check_ping(domain_name)

        if ping_result['status'] == 'down':
            alert_id = generate_alert_id('Ping', domain_name, 'down')
            if alert_id in config['acknowledged_alerts']:
                alert_details_map[alert_id] = {
                    'id': alert_id,
                    'type': 'Ping',
                    'domain': domain_name,
                    'status': 'down',
                    'message': f'Host {domain_name} is down'
                }

    # Move all acknowledged alerts to deleted_alerts list
    for alert_id in config['acknowledged_alerts']:
        if alert_id not in config['deleted_alerts']:
            config['deleted_alerts'].append(alert_id)

    # Record in alert history
    import database as db
    current_user = auth.get_current_user()
    user_id = current_user['id'] if current_user else None
    username = current_user['username'] if current_user else 'System'

    for alert_id, alert_details in alert_details_map.items():
        db.add_alert_history(
            alert_id=alert_id,
            domain_name=alert_details['domain'],
            alert_type=alert_details['type'].lower(),
            status=alert_details.get('status', 'warning'),
            message=alert_details['message'],
            action='deleted',
            user_id=user_id,
            username=username
        )

    # Clear the acknowledged alerts list
    config['acknowledged_alerts'] = []
    save_config(config)

    flash(f'Successfully deleted {deleted_count} acknowledged alerts', 'success')
    return redirect(url_for('alerts'))

@app.route('/restore_alert/<alert_id>', methods=['POST'])
@auth.login_required
def restore_alert(alert_id):
    """Restore a single deleted alert"""
    config = load_config()

    if 'deleted_alerts' not in config or alert_id not in config['deleted_alerts']:
        flash('Alert not found or already restored', 'warning')
        return redirect(url_for('archived_alerts'))

    # Get alert details
    alert_details = None

    # Check SSL certificate alerts
    for entry in config.get('ssl_domains', []):
        domain_name = entry.get('url')
        cert_status = check_certificate(domain_name)

        if cert_status.status in ['warning', 'expired', 'error']:
            temp_alert_id = generate_alert_id('SSL', domain_name, cert_status.status)
            if temp_alert_id == alert_id:
                alert_details = {
                    'id': alert_id,
                    'type': 'SSL',
                    'domain': domain_name,
                    'status': cert_status.status,
                    'message': f'SSL certificate for {domain_name} will expire in {cert_status.days_remaining} days' if cert_status.status == 'warning' else
                              f'SSL certificate for {domain_name} has expired' if cert_status.status == 'expired' else
                              f'Error checking SSL certificate for {domain_name}'
                }
                break

    # If not found, check domain expiry alerts
    if not alert_details:
        for entry in config.get('domain_expiry', []):
            domain_name = entry.get('name')
            domain_status = check_domain_expiry(domain_name)

            if domain_status.status in ['warning', 'expired', 'error']:
                temp_alert_id = generate_alert_id('Domain', domain_name, domain_status.status)
                if temp_alert_id == alert_id:
                    alert_details = {
                        'id': alert_id,
                        'type': 'Domain',
                        'domain': domain_name,
                        'status': domain_status.status,
                        'message': f'Domain {domain_name} will expire in {domain_status.days_remaining} days' if domain_status.status == 'warning' else
                                  f'Domain {domain_name} has expired' if domain_status.status == 'expired' else
                                  f'Error checking expiry for domain {domain_name}'
                    }
                    break

    # If still not found, check ping alerts
    if not alert_details:
        for entry in config.get('ping_hosts', []):
            domain_name = entry.get('host')
            ping_result = check_ping(domain_name)

            if ping_result['status'] == 'down':
                temp_alert_id = generate_alert_id('Ping', domain_name, 'down')
                if temp_alert_id == alert_id:
                    alert_details = {
                        'id': alert_id,
                        'type': 'Ping',
                        'domain': domain_name,
                        'status': 'down',
                        'message': f'Host {domain_name} is down'
                    }
                    break

    # Remove from deleted alerts list
    config['deleted_alerts'].remove(alert_id)
    save_config(config)

    # Record in alert history
    if alert_details:
        import database as db
        current_user = auth.get_current_user()
        user_id = current_user['id'] if current_user else None
        username = current_user['username'] if current_user else 'System'

        db.add_alert_history(
            alert_id=alert_id,
            domain_name=alert_details['domain'],
            alert_type=alert_details['type'].lower(),
            status=alert_details.get('status', 'warning'),
            message=alert_details['message'],
            action='restored',
            user_id=user_id,
            username=username
        )

    flash('Alert restored successfully', 'success')
    return redirect(url_for('archived_alerts'))

@app.route('/restore_deleted_alerts', methods=['POST'])
@auth.login_required
def restore_deleted_alerts():
    """Restore all deleted alerts"""
    config = load_config()

    if 'deleted_alerts' not in config or not config['deleted_alerts']:
        flash('No deleted alerts to restore', 'info')
        return redirect(url_for('archived_alerts'))

    # Count the number of alerts being restored
    restored_count = len(config['deleted_alerts'])

    # Get alert details for all deleted alerts
    alert_details_map = {}

    # Check SSL certificate alerts
    for entry in config.get('ssl_domains', []):
        domain_name = entry.get('url')
        cert_status = check_certificate(domain_name)

        if cert_status.status in ['warning', 'expired', 'error']:
            alert_id = generate_alert_id('SSL', domain_name, cert_status.status)
            if alert_id in config['deleted_alerts']:
                alert_details_map[alert_id] = {
                    'id': alert_id,
                    'type': 'SSL',
                    'domain': domain_name,
                    'status': cert_status.status,
                    'message': f'SSL certificate for {domain_name} will expire in {cert_status.days_remaining} days' if cert_status.status == 'warning' else
                              f'SSL certificate for {domain_name} has expired' if cert_status.status == 'expired' else
                              f'Error checking SSL certificate for {domain_name}'
                }

    # Check domain expiry alerts
    for entry in config.get('domain_expiry', []):
        domain_name = entry.get('name')
        domain_status = check_domain_expiry(domain_name)

        if domain_status.status in ['warning', 'expired', 'error']:
            alert_id = generate_alert_id('Domain', domain_name, domain_status.status)
            if alert_id in config['deleted_alerts']:
                alert_details_map[alert_id] = {
                    'id': alert_id,
                    'type': 'Domain',
                    'domain': domain_name,
                    'status': domain_status.status,
                    'message': f'Domain {domain_name} will expire in {domain_status.days_remaining} days' if domain_status.status == 'warning' else
                              f'Domain {domain_name} has expired' if domain_status.status == 'expired' else
                              f'Error checking expiry for domain {domain_name}'
                }

    # Check ping alerts
    for entry in config.get('ping_hosts', []):
        domain_name = entry.get('host')
        ping_result = check_ping(domain_name)

        if ping_result['status'] == 'down':
            alert_id = generate_alert_id('Ping', domain_name, 'down')
            if alert_id in config['deleted_alerts']:
                alert_details_map[alert_id] = {
                    'id': alert_id,
                    'type': 'Ping',
                    'domain': domain_name,
                    'status': 'down',
                    'message': f'Host {domain_name} is down'
                }

    # Record in alert history
    import database as db
    current_user = auth.get_current_user()
    user_id = current_user['id'] if current_user else None
    username = current_user['username'] if current_user else 'System'

    for alert_id, alert_details in alert_details_map.items():
        db.add_alert_history(
            alert_id=alert_id,
            domain_name=alert_details['domain'],
            alert_type=alert_details['type'].lower(),
            status=alert_details.get('status', 'warning'),
            message=alert_details['message'],
            action='restored',
            user_id=user_id,
            username=username
        )

    # Clear the deleted alerts list
    config['deleted_alerts'] = []
    save_config(config)

    flash(f'Successfully restored {restored_count} deleted alerts', 'success')
    return redirect(url_for('archived_alerts'))

@app.route('/archived_alerts')
@auth.login_required
def archived_alerts():
    """Archived Alerts page showing history of all alerts"""
    start_time = time.time()
    logger.debug("Starting archived alerts page load")

    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)

    # Calculate offset
    offset = (page - 1) * per_page

    # Get alert history from database
    import database as db
    alert_history = db.get_alert_history(limit=per_page, offset=offset)
    total_alerts = db.get_alert_history_count()

    # Calculate pagination info
    total_pages = (total_alerts + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages

    end_time = time.time()
    logger.debug(f"Archived alerts page loaded in {end_time - start_time:.2f} seconds")

    return render_template(
        'archived_alerts.html',
        alert_history=alert_history,
        page=page,
        per_page=per_page,
        total_alerts=total_alerts,
        total_pages=total_pages,
        has_prev=has_prev,
        has_next=has_next
    )

def get_alerts_count():
    """Count the number of active unacknowledged alerts in the system"""
    # Get current user and organization
    user = auth.get_current_user()
    if not user:
        return 0

    current_org = user.get('current_organization')
    if not current_org:
        return 0

    config = load_config()
    alerts_count = 0
    acknowledged_alerts = config.get('acknowledged_alerts', [])
    deleted_alerts = config.get('deleted_alerts', [])

    # Get domains from database for current organization only
    domains_from_db = db.get_domains_by_organization(current_org['id'])

    # Process each domain
    for domain in domains_from_db:
        domain_name = domain['name']

        # Check if domain is monitored for SSL
        if domain['ssl_monitored']:
            cert_status = check_certificate(domain_name)
            if cert_status.status in ['warning', 'expired', 'error']:
                alert_id = generate_alert_id('SSL', domain_name, cert_status.status)
                if alert_id not in acknowledged_alerts and alert_id not in deleted_alerts:
                    alerts_count += 1

        # Check if domain is monitored for expiry
        if domain['expiry_monitored']:
            domain_status = check_domain_expiry(domain_name)
            if domain_status.status in ['warning', 'expired', 'error']:
                alert_id = generate_alert_id('Domain', domain_name, domain_status.status)
                if alert_id not in acknowledged_alerts and alert_id not in deleted_alerts:
                    alerts_count += 1

        # Check if domain is monitored for ping
        if domain['ping_monitored']:
            ping_result = check_ping(domain_name)
            if ping_result['status'] == 'down':
                alert_id = generate_alert_id('Ping', domain_name, 'down')
                if alert_id not in acknowledged_alerts and alert_id not in deleted_alerts:
                    alerts_count += 1

    return alerts_count

@app.context_processor
def inject_alerts_count():
    """Inject alerts count into all templates"""
    return {'alerts_count': get_alerts_count()}

@app.context_processor
def inject_user():
    """Inject current user into all templates"""
    try:
        current_user = auth.get_current_user()
        return {'user': current_user}
    except:
        return {'user': None}

@app.route('/')
@auth.login_required
def index():
    """Dashboard page showing overview of all monitoring"""
    start_time = time.time()
    logger.debug("Starting dashboard page load")

    # Clear any "You have been logged out" messages that might have persisted
    if '_flashes' in session:
        flashes = session.get('_flashes', [])
        session['_flashes'] = [(category, message) for category, message in flashes
                              if message != 'You have been logged out']

    # Get current user
    current_user = auth.get_current_user()

    # Get user's organizations
    user_orgs = current_user.get('organizations', [])

    # If user has no organizations, redirect to create first organization
    if not user_orgs and not current_user['is_admin']:
        flash("You need to create an organization before you can use Certifly", 'info')
        return redirect(url_for('create_first_organization'))

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domains for current organization
    domains_from_db = db.get_domains_by_organization(current_org['id'])

    config = load_config()
    ssl_domains = {}
    domain_expiry = {}
    ping_hosts = {}

    # Initialize all_domains list
    all_domains = []

    # Process domains from database
    for domain in domains_from_db:
        domain_name = domain['name']
        domain_id = domain['id']

        # Check if domain is monitored for SSL
        ssl_status = None
        if domain['ssl_monitored']:
            ssl_status = check_certificate(domain_name)
            ssl_domains[domain_name] = ssl_status

        # Check if domain is monitored for expiry
        domain_status = None
        if domain['expiry_monitored']:
            domain_status = check_domain_expiry(domain_name)
            domain_expiry[domain_name] = domain_status

        # Check if domain is monitored for ping
        ping_status = 'unknown'
        if domain['ping_monitored']:
            ping_result = check_ping(domain_name)
            ping_status = ping_result['status']
            ping_hosts[domain_name] = ping_result

        # Determine if this domain has any issues
        has_issues = False
        if ssl_status and ssl_status.status in ['warning', 'expired', 'error']:
            has_issues = True
        if domain_status and domain_status.status in ['warning', 'expired', 'error']:
            has_issues = True
        if ping_status == 'down':
            has_issues = True

        # Determine expiry status for display
        expiry_status = 'unknown'
        days_until_expiry = 0
        if domain_status:
            expiry_status = domain_status.status
            days_until_expiry = domain_status.days_remaining

        # Get uptime statistics
        uptime_percentage = db.calculate_uptime_percentage(domain_name)
        if uptime_percentage is not None:
            uptime_percentage = round(uptime_percentage, 1)

        # Get ping history for uptime segments
        ping_history = db.get_ping_history(domain_name, hours=12)

        # Create uptime segments (12 segments representing the last 12 hours)
        uptime_segments = []
        if ping_history:
            # Group history into 12 hourly segments
            current_time = datetime.now()
            for i in range(12, 0, -1):
                segment_start = current_time - timedelta(hours=i)
                segment_end = current_time - timedelta(hours=i-1)

                # Find ping entries in this segment
                segment_entries = [entry for entry in ping_history
                                  if entry['checked_at'] and
                                  segment_start <= datetime.fromtimestamp(entry['checked_at']) < segment_end]

                # Determine segment status
                if segment_entries:
                    # If any entry is down, the segment is down
                    if any(entry['status'] == 'down' for entry in segment_entries):
                        uptime_segments.append('down')
                    else:
                        uptime_segments.append('up')
                else:
                    uptime_segments.append('unknown')

        # Add domain to the list
        all_domains.append({
            'id': domain_id,
            'name': domain_name,
            'ssl_status': ssl_status,
            'domain_status': domain_status,
            'has_issues': has_issues,
            'expiry_status': expiry_status,
            'days_until_expiry': days_until_expiry,
            'health_status': ping_status,
            'uptime_percentage': uptime_percentage,
            'uptime_segments': uptime_segments
        })



    # Sort domains with issues first
    all_domains.sort(key=lambda x: (0 if x['has_issues'] else 1, x['name']))

    # Count active alerts (only unacknowledged ones)
    active_alerts = []
    acknowledged_alerts = config.get('acknowledged_alerts', [])
    deleted_alerts = config.get('deleted_alerts', [])

    # SSL certificate alerts
    for cert in ssl_domains.values():
        if cert.status in ['warning', 'expired', 'error']:
            alert_id = generate_alert_id('SSL', cert.domain, cert.status)
            if alert_id not in acknowledged_alerts and alert_id not in deleted_alerts:
                active_alerts.append(cert)

    # Domain expiry alerts
    for domain in domain_expiry.values():
        if domain.status in ['warning', 'expired', 'error']:
            alert_id = generate_alert_id('Domain', domain.name, domain.status)
            if alert_id not in acknowledged_alerts and alert_id not in deleted_alerts:
                active_alerts.append(domain)

    # Ping alerts
    for domain_name, host_data in ping_hosts.items():
        if host_data.get('status') == 'down':
            alert_id = generate_alert_id('Ping', domain_name, 'down')
            if alert_id not in acknowledged_alerts and alert_id not in deleted_alerts:
                # Create a simple object for ping alerts
                class PingAlert:
                    def __init__(self, domain, status):
                        self.domain = domain
                        self.status = status

                active_alerts.append(PingAlert(domain_name, 'down'))

    end_time = time.time()
    logger.debug(f"Dashboard page loaded in {end_time - start_time:.2f} seconds")

    return render_template('index.html',
                         domains=all_domains,
                         alerts=active_alerts,
                         user=current_user)

# Email settings route removed - functionality moved to notifications page

@app.route('/ssl_certificates')
@auth.login_required
def ssl_certificates():
    """SSL Certificate monitoring page"""
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domains for current organization that have SSL monitoring enabled
    domains = db.get_domains_by_organization(current_org['id'])
    certificates = []

    for domain in domains:
        if domain['ssl_monitored']:
            cert_status = check_certificate(domain['name'])
            certificates.append(cert_status)

    return render_template('ssl_certificates.html', certificates=certificates, user=current_user)

@app.route('/domain_expiry')
@auth.login_required
def domain_expiry():
    """Domain expiry monitoring page"""
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domains for current organization that have domain expiry monitoring enabled
    domains_from_db = db.get_domains_by_organization(current_org['id'])
    domains = []

    for domain in domains_from_db:
        if domain['expiry_monitored']:
            domain_status = check_domain_expiry(domain['name'])
            domains.append(domain_status)

    return render_template('domain_expiry.html', domains=domains, user=current_user)

@app.route('/ping_monitoring')
@auth.login_required
def ping_monitoring():
    """Ping monitoring page"""
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domains for current organization that have ping monitoring enabled
    domains_from_db = db.get_domains_by_organization(current_org['id'])
    ping_results = []

    for domain in domains_from_db:
        if domain['ping_monitored']:
            ping_result = check_ping(domain['name'])
            # Create a new dictionary with all the ping result data plus the host
            result_with_host = {
                'host': domain['name'],
                'status': ping_result['status'],
                'response_time': ping_result['response_time'],
                'last_checked': ping_result['last_checked']
            }
            ping_results.append(result_with_host)

    ping_stats = get_ping_stats(ping_results)
    return render_template('ping_monitoring.html', ping_results=ping_results, ping_stats=ping_stats, user=current_user)

@app.route('/domain/<int:domain_id>')
@auth.login_required
def domain_details(domain_id):
    """Domain details page showing comprehensive information about a specific domain"""
    try:
        start_time = time.time()
        logger.debug(f"Starting domain details page load for domain ID {domain_id}")

        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            flash("You don't have access to any organizations", 'error')
            return redirect(url_for('profile'))

        # Get domain by ID
        domain = db.get_domain_by_id(domain_id)
        if not domain:
            flash('Domain not found', 'error')
            return redirect(url_for('index'))

        # Check if domain belongs to current organization
        if domain['organization_id'] != current_org['id']:
            flash("You don't have permission to view this domain", 'error')
            return redirect(url_for('index'))

        domain_to_get = domain['name']

        # Determine which monitoring services are enabled for this domain
        monitors = []

        # Check if domain is monitored for SSL
        ssl_status = None
        if domain['ssl_monitored']:
            monitors.append('ssl')
            ssl_status = check_certificate(domain_to_get)

        # Check if domain is monitored for expiry
        domain_status = None
        if domain['expiry_monitored']:
            monitors.append('expiry')
            domain_status = check_domain_expiry(domain_to_get)

        # Check if domain is monitored for ping
        ping_status = "unknown"
        ping_response_time = 0.0
        if domain['ping_monitored']:
            monitors.append('ping')
            # If we already have ping status from SSL or domain check, use that
            if ssl_status:
                ping_status = ssl_status.ping_status
            elif domain_status:
                ping_status = domain_status.ping_status
            else:
                # Only do a separate ping check if we don't already have the status
                ping_result = check_ping(domain_to_get)
                ping_status = ping_result["status"]
                ping_response_time = ping_result["response_time"]

        # Get uptime statistics
        uptime_percentage = db.calculate_uptime_percentage(domain_to_get)
        if uptime_percentage is not None:
            uptime_percentage = round(uptime_percentage, 1)

        # Get ping history for uptime segments
        ping_history = db.get_ping_history(domain_to_get, hours=12)

        # Create uptime segments (12 segments representing the last 12 hours)
        uptime_segments = []
        if ping_history:
            # Group history into 12 hourly segments
            current_time = datetime.now()

            for i in range(12):
                segment_start = current_time - timedelta(hours=12-i)
                segment_end = current_time - timedelta(hours=11-i)

                # Find all checks in this segment
                segment_checks = [check for check in ping_history
                                if check['checked_at'] and
                                segment_start <= datetime.fromtimestamp(check['checked_at']) < segment_end]

                if segment_checks:
                    # If any check is down, the segment is down
                    if any(check['status'] == 'down' for check in segment_checks):
                        uptime_segments.append('down')
                    else:
                        uptime_segments.append('up')
                else:
                    # No checks in this segment
                    uptime_segments.append('unknown')
        else:
            # If no history, use current status for all segments
            uptime_segments = [ping_status] * 12

        # Get timeframe parameter for the template
        timeframe_hours = request.args.get('timeframe', '24')
        try:
            timeframe_hours = int(timeframe_hours)
            if timeframe_hours not in [24, 168, 720]:  # 24h, 7d, 30d
                timeframe_hours = 24
        except ValueError:
            timeframe_hours = 24

        # Get 24-hour uptime percentage
        uptime_24h = db.calculate_uptime_percentage(domain_to_get, hours=24)
        if uptime_24h is not None:
            uptime_24h = round(uptime_24h, 1)

        # Get 7-day uptime percentage
        uptime_7d = db.calculate_uptime_percentage(domain_to_get, hours=24*7)
        if uptime_7d is not None:
            uptime_7d = round(uptime_7d, 1)

        # Get 30-day uptime percentage
        uptime_30d = db.calculate_uptime_percentage(domain_to_get, hours=24*30)
        if uptime_30d is not None:
            uptime_30d = round(uptime_30d, 1)

        # Determine if this domain has any issues
        has_issues = False
        if ssl_status and ssl_status.status in ['warning', 'expired', 'error']:
            has_issues = True
        if domain_status and domain_status.status in ['warning', 'expired', 'error']:
            has_issues = True
        if ping_status == 'down':
            has_issues = True

        # Determine expiry status for display
        expiry_status = 'unknown'
        days_until_expiry = 0
        if domain_status:
            expiry_status = domain_status.status
            # Ensure days_until_expiry is an integer
            if domain_status.days_remaining is not None:
                days_until_expiry = domain_status.days_remaining
            else:
                days_until_expiry = 0

        # Get user's timezone setting
        app_settings = get_app_settings()
        user_timezone = app_settings.timezone

        # Convert dates to user's timezone if needed
        if ssl_status and ssl_status.expiry_date:
            ssl_status.expiry_date = convert_to_user_timezone(ssl_status.expiry_date, user_timezone)

        if domain_status and domain_status.expiry_date:
            domain_status.expiry_date = convert_to_user_timezone(domain_status.expiry_date, user_timezone)

        # Perform a fresh ping check to ensure we have the latest data
        fresh_ping_result = check_ping(domain_to_get)
        ping_status = fresh_ping_result.get('status', 'unknown')
        ping_response_time = fresh_ping_result.get('response_time', 0)

        # Create domain data object with safe defaults for None values
        domain_data = {
            'id': domain_id,
            'name': domain_to_get,
            'monitors': monitors,
            'ssl_status': ssl_status if ssl_status is not None else {
                'status': 'unknown',
                'days_remaining': 0,
                'expiry_date': None
            },
            'domain_status': domain_status if domain_status is not None else {
                'status': 'unknown',
                'days_remaining': 0,
                'expiry_date': None,
                'registrar': 'Unknown'
            },
            'has_issues': has_issues,
            'expiry_status': expiry_status,
            'days_until_expiry': days_until_expiry,
            'health_status': ping_status,
            'response_time': ping_response_time,
            'timeframe_hours': timeframe_hours,
            'uptime_percentage': uptime_percentage,
            'uptime_24h': uptime_24h,
            'uptime_7d': uptime_7d,
            'uptime_30d': uptime_30d,
            'uptime_segments': uptime_segments
        }

        end_time = time.time()
        logger.debug(f"Domain details page for {domain_to_get} loaded in {end_time - start_time:.2f} seconds")

        # Get user's timezone setting
        app_settings = get_app_settings()
        user_timezone = app_settings.timezone

        return render_template('domain_details.html',
                              domain=domain_data,
                              user=current_user,
                              user_timezone=user_timezone)
    except Exception as e:
        logger.error(f"Error loading domain details page: {str(e)}", exc_info=True)
        flash(f'Error loading domain details: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/add_ssl_domain', methods=['POST'])
def add_ssl_domain():
    domain = request.form.get('url')

    if not domain:
        flash('Domain name is required', 'error')
        return redirect(url_for('ssl_certificates'))

    # Clean the domain
    domain = clean_domain_name(domain)
    if not domain:
        flash('Invalid domain format', 'error')
        return redirect(url_for('ssl_certificates'))

    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Check if domain already exists in this organization
    existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
    if existing_domain:
        # If domain exists, update it to enable SSL monitoring
        db.update_domain(existing_domain['id'], domain, True, existing_domain['expiry_monitored'], existing_domain['ping_monitored'])
        flash(f'Domain {domain} updated to include SSL monitoring', 'success')
    else:
        # Add new domain with SSL monitoring enabled
        domain_id = db.add_domain(domain, current_org['id'], True, False, False)
        if domain_id:
            flash(f'Domain {domain} added successfully for SSL monitoring', 'success')
        else:
            flash(f'Error adding domain {domain}', 'error')

    return redirect(url_for('ssl_certificates'))

@app.route('/remove_ssl_domain/<domain>')
def remove_ssl_domain(domain):
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domain by name and organization
    existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
    if existing_domain:
        # If domain has other monitoring enabled, just disable SSL monitoring
        if existing_domain['expiry_monitored'] or existing_domain['ping_monitored']:
            db.update_domain(existing_domain['id'], domain, False, existing_domain['expiry_monitored'], existing_domain['ping_monitored'])
            flash(f'Domain {domain} removed from SSL monitoring', 'success')
        else:
            # If no other monitoring is enabled, delete the domain
            db.delete_domain(existing_domain['id'])
            flash(f'Domain {domain} removed from all monitoring', 'success')
    else:
        flash(f'Domain {domain} not found', 'error')

    return redirect(url_for('ssl_certificates'))

@app.route('/refresh_ssl_certificate/<domain>')
def refresh_ssl_certificate(domain):
    """Refresh SSL certificate data for a specific domain"""
    try:
        cert_status = check_certificate(domain)
        return jsonify({
            'success': True,
            'data': {
                'status': cert_status.status,
                'days_remaining': cert_status.days_remaining,
                'expiry_date': cert_status.expiry_date.strftime('%Y-%m-%d')
            }
        })
    except Exception as e:
        logger.error(f"Error refreshing SSL certificate for {domain}: {str(e)}")
        return jsonify({
            'success': False,
            'message': f"Error refreshing certificate: {str(e)}"
        }), 500

@app.route('/api/ssl/<domain>/refresh', methods=['POST'])
def api_refresh_ssl_certificate(domain):
    """API endpoint to refresh SSL certificate data for a specific domain"""
    try:
        # Clear SSL cache for this domain to force a fresh check
        if domain in SSL_CACHE:
            del SSL_CACHE[domain]
            save_ssl_cache(SSL_CACHE)

        cert_status = check_certificate(domain)
        return jsonify({
            'success': True,
            'data': {
                'status': cert_status.status,
                'days_remaining': cert_status.days_remaining,
                'expiry_date': cert_status.expiry_date.strftime('%Y-%m-%d')
            }
        })
    except Exception as e:
        logger.error(f"Error refreshing SSL certificate for {domain}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Error refreshing certificate: {str(e)}"
        }), 500

@app.route('/bulk_import_ssl', methods=['POST'])
def bulk_import_ssl():
    domains_text = request.form.get('domains')
    if not domains_text:
        flash('No domains provided', 'error')
        return redirect(url_for('ssl_certificates'))

    # Split by newlines, commas, or spaces
    domains = re.split(r'[\n,\s]+', domains_text)
    domains = [d.strip() for d in domains if d.strip()]

    if not domains:
        flash('No valid domains found', 'error')
        return redirect(url_for('ssl_certificates'))

    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    added_count = 0
    updated_count = 0
    skipped_count = 0

    for domain in domains:
        # Clean the domain
        domain = clean_domain_name(domain)
        if not domain:
            continue

        # Check if domain already exists in this organization
        existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
        if existing_domain:
            # If domain exists and SSL monitoring is not enabled, update it
            if not existing_domain['ssl_monitored']:
                db.update_domain(existing_domain['id'], domain, True, existing_domain['expiry_monitored'], existing_domain['ping_monitored'])
                updated_count += 1
            else:
                skipped_count += 1
        else:
            # Add new domain with SSL monitoring enabled
            domain_id = db.add_domain(domain, current_org['id'], True, False, False)
            if domain_id:
                added_count += 1
            else:
                skipped_count += 1

    if added_count > 0 or updated_count > 0:
        message = []
        if added_count > 0:
            message.append(f'Added {added_count} new domains')
        if updated_count > 0:
            message.append(f'Updated {updated_count} existing domains')
        if skipped_count > 0:
            message.append(f'Skipped {skipped_count} domains')

        flash(', '.join(message) + ' for SSL monitoring', 'success')
    else:
        flash(f'No domains added or updated, skipped {skipped_count} domains', 'warning')

    return redirect(url_for('ssl_certificates'))

@app.route('/export_ssl_domains')
def export_ssl_domains():
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domains for current organization that have SSL monitoring enabled
    domains_from_db = db.get_domains_by_organization(current_org['id'])
    domains = [domain['name'] for domain in domains_from_db if domain['ssl_monitored']]
    domains_text = '\n'.join(domains)

    response = app.response_class(
        response=domains_text,
        status=200,
        mimetype='text/plain'
    )
    response.headers["Content-Disposition"] = "attachment; filename=ssl_domains.txt"
    return response

@app.route('/add_expiry_domain', methods=['POST'])
def add_expiry_domain():
    domain = request.form.get('domain')

    if not domain:
        flash('Domain name is required', 'error')
        return redirect(url_for('domain_expiry'))

    # Clean the domain
    domain = clean_domain_name(domain)
    if not domain:
        flash('Invalid domain format', 'error')
        return redirect(url_for('domain_expiry'))

    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Check if domain already exists in this organization
    existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
    if existing_domain:
        # If domain exists, update it to enable expiry monitoring
        db.update_domain(existing_domain['id'], domain, existing_domain['ssl_monitored'], True, existing_domain['ping_monitored'])
        flash(f'Domain {domain} updated to include expiry monitoring', 'success')
    else:
        # Add new domain with expiry monitoring enabled
        domain_id = db.add_domain(domain, current_org['id'], False, True, False)
        if domain_id:
            flash(f'Domain {domain} added successfully for expiry monitoring', 'success')
        else:
            flash(f'Error adding domain {domain}', 'error')

    return redirect(url_for('domain_expiry'))

@app.route('/remove_expiry_domain/<domain>')
def remove_expiry_domain(domain):
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domain by name and organization
    existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
    if existing_domain:
        # If domain has other monitoring enabled, just disable expiry monitoring
        if existing_domain['ssl_monitored'] or existing_domain['ping_monitored']:
            db.update_domain(existing_domain['id'], domain, existing_domain['ssl_monitored'], False, existing_domain['ping_monitored'])
            flash(f'Domain {domain} removed from expiry monitoring', 'success')
        else:
            # If no other monitoring is enabled, delete the domain
            db.delete_domain(existing_domain['id'])
            flash(f'Domain {domain} removed from all monitoring', 'success')
    else:
        flash(f'Domain {domain} not found', 'error')

    return redirect(url_for('domain_expiry'))

@app.route('/api/expiry/<domain>/refresh', methods=['POST'])
def api_refresh_domain_expiry(domain):
    """API endpoint to refresh domain expiry data for a specific domain"""
    try:
        # Clear domain expiry cache for this domain to force a fresh check
        if domain in DOMAIN_EXPIRY_CACHE:
            del DOMAIN_EXPIRY_CACHE[domain]
            save_domain_expiry_cache(DOMAIN_EXPIRY_CACHE)

        domain_status = check_domain_expiry(domain)
        return jsonify({
            'success': True,
            'data': {
                'status': domain_status.status,
                'days_remaining': domain_status.days_remaining,
                'expiry_date': domain_status.expiry_date.strftime('%Y-%m-%d'),
                'registrar': domain_status.registrar
            }
        })
    except Exception as e:
        logger.error(f"Error refreshing domain expiry for {domain}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Error refreshing domain expiry: {str(e)}"
        }), 500

@app.route('/bulk_import_expiry', methods=['POST'])
def bulk_import_expiry():
    domains_text = request.form.get('domains')
    if not domains_text:
        flash('No domains provided', 'error')
        return redirect(url_for('domain_expiry'))

    # Split by newlines, commas, or spaces
    domains = re.split(r'[\n,\s]+', domains_text)
    domains = [d.strip() for d in domains if d.strip()]

    if not domains:
        flash('No valid domains found', 'error')
        return redirect(url_for('domain_expiry'))

    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    added_count = 0
    updated_count = 0
    skipped_count = 0

    for domain in domains:
        # Clean the domain
        domain = clean_domain_name(domain)
        if not domain:
            continue

        # Check if domain already exists in this organization
        existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
        if existing_domain:
            # If domain exists and expiry monitoring is not enabled, update it
            if not existing_domain['expiry_monitored']:
                db.update_domain(existing_domain['id'], domain, existing_domain['ssl_monitored'], True, existing_domain['ping_monitored'])
                updated_count += 1
            else:
                skipped_count += 1
        else:
            # Add new domain with expiry monitoring enabled
            domain_id = db.add_domain(domain, current_org['id'], False, True, False)
            if domain_id:
                added_count += 1
            else:
                skipped_count += 1

    if added_count > 0 or updated_count > 0:
        message = []
        if added_count > 0:
            message.append(f'Added {added_count} new domains')
        if updated_count > 0:
            message.append(f'Updated {updated_count} existing domains')
        if skipped_count > 0:
            message.append(f'Skipped {skipped_count} domains')

        flash(', '.join(message) + ' for expiry monitoring', 'success')
    else:
        flash(f'No domains added or updated, skipped {skipped_count} domains', 'warning')

    return redirect(url_for('domain_expiry'))

@app.route('/export_expiry_domains')
def export_expiry_domains():
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domains for current organization that have expiry monitoring enabled
    domains_from_db = db.get_domains_by_organization(current_org['id'])
    domains = [domain['name'] for domain in domains_from_db if domain['expiry_monitored']]
    domains_text = '\n'.join(domains)

    response = app.response_class(
        response=domains_text,
        status=200,
        mimetype='text/plain'
    )
    response.headers["Content-Disposition"] = "attachment; filename=domain_expiry.txt"
    return response

@app.route('/add_ping_host', methods=['POST'])
def add_ping_host():
    host = request.form.get('host')

    if not host:
        flash('Host is required', 'error')
        return redirect(url_for('ping_monitoring'))

    # Clean the host
    host = clean_domain_name(host)
    if not host:
        flash('Invalid host format', 'error')
        return redirect(url_for('ping_monitoring'))

    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Check if host already exists in this organization
    existing_domain = db.get_domain_by_name_and_org(host, current_org['id'])
    if existing_domain:
        # If domain exists, update it to enable ping monitoring
        db.update_domain(existing_domain['id'], host, existing_domain['ssl_monitored'], existing_domain['expiry_monitored'], True)
        flash(f'Host {host} updated to include ping monitoring', 'success')
    else:
        # Add new domain with ping monitoring enabled
        domain_id = db.add_domain(host, current_org['id'], False, False, True)
        if domain_id:
            flash(f'Host {host} added successfully for ping monitoring', 'success')
        else:
            flash(f'Error adding host {host}', 'error')

    return redirect(url_for('ping_monitoring'))

@app.route('/remove_ping_host/<host>')
def remove_ping_host(host):
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domain by name and organization
    existing_domain = db.get_domain_by_name_and_org(host, current_org['id'])
    if existing_domain:
        # If domain has other monitoring enabled, just disable ping monitoring
        if existing_domain['ssl_monitored'] or existing_domain['expiry_monitored']:
            db.update_domain(existing_domain['id'], host, existing_domain['ssl_monitored'], existing_domain['expiry_monitored'], False)
            flash(f'Host {host} removed from ping monitoring', 'success')
        else:
            # If no other monitoring is enabled, delete the domain
            db.delete_domain(existing_domain['id'])
            flash(f'Host {host} removed from all monitoring', 'success')
    else:
        flash(f'Host {host} not found', 'error')

    return redirect(url_for('ping_monitoring'))

@app.route('/api/ping/<host>/refresh', methods=['POST'])
def api_refresh_ping_host(host):
    """API endpoint to refresh ping status for a specific host"""
    try:
        # Clear ping cache for this host to force a fresh check
        if host in PING_CACHE:
            del PING_CACHE[host]
            save_ping_cache(PING_CACHE)

        ping_result = check_ping(host)

        # Get uptime percentage
        uptime_percentage = db.calculate_uptime_percentage(host)
        if uptime_percentage is not None:
            uptime_percentage = round(uptime_percentage, 1)

        # Get ping history for uptime segments
        ping_history = db.get_ping_history(host, hours=12)

        # Create uptime segments (12 segments representing the last 12 hours)
        uptime_segments = []
        if ping_history:
            # Group history into 12 hourly segments
            current_time = datetime.now()

            for i in range(12):
                segment_start = current_time - timedelta(hours=12-i)
                segment_end = current_time - timedelta(hours=11-i)

                # Find all checks in this segment
                segment_checks = [check for check in ping_history
                                if check['checked_at'] and
                                segment_start <= datetime.fromtimestamp(check['checked_at']) < segment_end]

                if segment_checks:
                    # If any check is down, the segment is down
                    if any(check['status'] == 'down' for check in segment_checks):
                        uptime_segments.append('down')
                    else:
                        uptime_segments.append('up')
                else:
                    # No checks in this segment
                    uptime_segments.append('unknown')
        else:
            # If no history, use current status for all segments
            uptime_segments = [ping_result["status"]] * 12

        # Get response history from config
        config = load_config()
        ping_hosts = config.get('ping_hosts', [])
        response_history = []

        for ping_host in ping_hosts:
            if ping_host.get('host') == host:
                # Initialize response history if it doesn't exist
                if 'response_history' not in ping_host:
                    ping_host['response_history'] = []

                # Add new response time to history (keep last 20 entries)
                if ping_result["status"] == "up":
                    ping_host['response_history'].append(ping_result["response_time"])
                    # Keep only the last 20 entries
                    ping_host['response_history'] = ping_host['response_history'][-20:]

                response_history = ping_host.get('response_history', [])

                # Save the updated config
                save_config(config)
                break

        return jsonify({
            'success': True,
            'data': {
                'host': host,
                'ping_status': ping_result["status"],
                'response_time': ping_result["response_time"],
                'response_history': response_history,
                'uptime_percentage': uptime_percentage,
                'uptime_segments': uptime_segments,
                'last_checked': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except Exception as e:
        logger.error(f"Error refreshing ping status for {host}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Error refreshing ping status: {str(e)}"
        }), 500

@app.route('/bulk_import_ping', methods=['POST'])
def bulk_import_ping():
    hosts_text = request.form.get('hosts')
    if not hosts_text:
        flash('No hosts provided', 'error')
        return redirect(url_for('ping_monitoring'))

    # Split by newlines, commas, or spaces
    hosts = re.split(r'[\n,\s]+', hosts_text)
    hosts = [h.strip() for h in hosts if h.strip()]

    if not hosts:
        flash('No valid hosts found', 'error')
        return redirect(url_for('ping_monitoring'))

    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    added_count = 0
    updated_count = 0
    skipped_count = 0

    for host in hosts:
        # Clean the host
        host = clean_domain_name(host)
        if not host:
            continue

        # Check if host already exists in this organization
        existing_domain = db.get_domain_by_name_and_org(host, current_org['id'])
        if existing_domain:
            # If domain exists and ping monitoring is not enabled, update it
            if not existing_domain['ping_monitored']:
                db.update_domain(existing_domain['id'], host, existing_domain['ssl_monitored'], existing_domain['expiry_monitored'], True)
                updated_count += 1
            else:
                skipped_count += 1
        else:
            # Add new domain with ping monitoring enabled
            domain_id = db.add_domain(host, current_org['id'], False, False, True)
            if domain_id:
                added_count += 1
            else:
                skipped_count += 1

    if added_count > 0 or updated_count > 0:
        message = []
        if added_count > 0:
            message.append(f'Added {added_count} new hosts')
        if updated_count > 0:
            message.append(f'Updated {updated_count} existing hosts')
        if skipped_count > 0:
            message.append(f'Skipped {skipped_count} hosts')

        flash(', '.join(message) + ' for ping monitoring', 'success')
    else:
        flash(f'No hosts added or updated, skipped {skipped_count} hosts', 'warning')

    return redirect(url_for('ping_monitoring'))

@app.route('/export_ping_hosts')
def export_ping_hosts():
    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Get domains for current organization that have ping monitoring enabled
    domains_from_db = db.get_domains_by_organization(current_org['id'])
    hosts = [domain['name'] for domain in domains_from_db if domain['ping_monitored']]
    hosts_text = '\n'.join(hosts)

    response = app.response_class(
        response=hosts_text,
        status=200,
        mimetype='text/plain'
    )
    response.headers["Content-Disposition"] = "attachment; filename=ping_hosts.txt"
    return response

@app.route('/api/ping/<host>/response_history')
def api_ping_response_history(host):
    """API endpoint to get ping response time history for a specific host"""
    try:
        # Get timeframe from query parameter
        timeframe_hours = request.args.get('timeframe', '24')
        try:
            timeframe_hours = int(timeframe_hours)
            if timeframe_hours not in [24, 168, 720]:  # 24h, 7d, 30d
                timeframe_hours = 24
        except ValueError:
            timeframe_hours = 24

        # Perform a fresh ping check to ensure we have the latest data
        fresh_ping_result = check_ping(host)
        logger.debug(f"Fresh ping check for {host}: {fresh_ping_result}")

        # Get response time history
        response_history = db.get_ping_response_history(host, hours=timeframe_hours)

        # Add the fresh ping result to the response history if it was successful
        if fresh_ping_result.get('status') == 'up':
            # Create a new entry with the current timestamp
            fresh_entry = {
                'timestamp': int(time.time() * 1000),  # Current time in milliseconds
                'response_time': fresh_ping_result.get('response_time', 0),
                'formatted_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'iso_time': datetime.now().isoformat() + 'Z'  # Add 'Z' to indicate UTC
            }

            # Add the fresh entry to the response history
            response_history.append(fresh_entry)

            # Sort the response history by timestamp
            response_history.sort(key=lambda x: x.get('timestamp', 0))

        return jsonify({
            'success': True,
            'data': response_history
        })
    except Exception as e:
        logger.error(f"Error getting ping response history for {host}: {str(e)}")
        return jsonify({
            'success': False,
            'error': f"Error getting ping response history: {str(e)}"
        }), 500



@app.route('/app_settings', methods=['GET', 'POST'])
@auth.login_required
def app_settings():
    """Application settings page"""
    # Get current user and organization
    user = auth.get_current_user()
    current_org = user.get('current_organization')

    if request.method == 'POST':
        form_type = request.form.get('form_type')
        config = load_config()

        if form_type == 'monitoring_settings':
            # Update app settings
            if 'app_settings' not in config:
                config['app_settings'] = {}

            # Handle warning threshold safely
            try:
                warning_threshold = int(request.form.get('warning_threshold', 10))
            except (ValueError, TypeError):
                logger.warning(f"Invalid warning_threshold value: {request.form.get('warning_threshold')}. Using default value of 10.")
                warning_threshold = 10

            # Handle auto refresh interval safely
            try:
                auto_refresh_interval = int(request.form.get('auto_refresh_interval', 5))
            except (ValueError, TypeError):
                logger.warning(f"Invalid auto_refresh_interval value: {request.form.get('auto_refresh_interval')}. Using default value of 5.")
                auto_refresh_interval = 5

            # Get timezone setting
            timezone = request.form.get('timezone', 'UTC')
            # Validate timezone (use UTC as fallback if invalid)
            try:
                import pytz
                if timezone not in pytz.all_timezones:
                    logger.warning(f"Invalid timezone: {timezone}. Using default value of UTC.")
                    timezone = 'UTC'
            except ImportError:
                # If pytz is not available, accept any timezone value
                logger.warning("pytz not available, timezone validation skipped")

            config['app_settings']['warning_threshold_days'] = warning_threshold
            config['app_settings']['auto_refresh_enabled'] = 'auto_refresh_enabled' in request.form
            config['app_settings']['auto_refresh_interval'] = auto_refresh_interval
            config['app_settings']['timezone'] = timezone

            # Get WHOIS API key
            whois_api_key = request.form.get('whois_api_key', '').strip()

            # Save the WHOIS API key for the current organization
            if current_org:
                org_id = current_org['id']
                db.set_organization_setting(org_id, 'whois_api_key', whois_api_key)

                # Log the API key status (without revealing the actual key)
                if whois_api_key:
                    logger.info(f"WHOIS API key updated successfully for organization {org_id}")
                    # Removed success notification for WHOIS API key
                else:
                    logger.warning(f"WHOIS API key was cleared or not provided for organization {org_id}")
                    flash('Warning: No WHOIS API key provided. Domain expiry monitoring will not work correctly.', 'warning')
            else:
                # Fallback to global settings if no organization is selected
                if 'api_settings' not in config:
                    config['api_settings'] = {}

                config['api_settings']['whois_api_key'] = whois_api_key
                db.set_setting('api_settings', {'whois_api_key': whois_api_key})

                if whois_api_key:
                    logger.info("WHOIS API key updated successfully in global settings")
                    # Removed success notification for WHOIS API key
                else:
                    logger.warning("WHOIS API key was cleared or not provided in global settings")
                    flash('Warning: No WHOIS API key provided. Domain expiry monitoring will not work correctly.', 'warning')

            save_config(config)
            flash('Settings updated successfully', 'success')

        return redirect(url_for('app_settings'))

    settings = get_app_settings()

    # Get warning threshold from email settings for backward compatibility
    email_settings = get_email_settings()
    warning_threshold = email_settings.warning_threshold_days

    # Get WHOIS API key - first try organization-specific, then fall back to global
    whois_api_key = ''
    if current_org:
        org_id = current_org['id']
        whois_api_key = db.get_organization_setting(org_id, 'whois_api_key', '')

    # If no organization-specific key, check global settings
    if not whois_api_key:
        api_settings = db.get_setting('api_settings', {})
        whois_api_key = api_settings.get('whois_api_key', '')

    # Settings for the template
    # Get timezone display name
    timezone_display = settings.timezone
    try:
        import pytz
        if settings.timezone in pytz.all_timezones:
            # Find the city/region name from the timezone
            timezone_parts = settings.timezone.split('/')
            if len(timezone_parts) > 1:
                city = timezone_parts[-1].replace('_', ' ')
                # Get UTC offset
                tz = pytz.timezone(settings.timezone)
                utc_offset = datetime.now(tz).strftime('%z')
                # Format offset as +/-HH:MM
                if utc_offset:
                    offset_hours = utc_offset[:3]
                    offset_minutes = utc_offset[3:]
                    formatted_offset = f"{offset_hours}:{offset_minutes}"
                    timezone_display = f"{city} (UTC {formatted_offset})"
                else:
                    timezone_display = f"{city} (UTC)"
            # Special case for UTC
            elif settings.timezone == 'UTC':
                timezone_display = "UTC (+00:00)"
    except (ImportError, Exception) as e:
        logger.warning(f"Error formatting timezone display name: {str(e)}")

    combined_settings = {
        'auto_refresh_enabled': settings.auto_refresh_enabled,
        'auto_refresh_interval': settings.auto_refresh_interval,
        'theme': settings.theme,
        'timezone': settings.timezone,
        'timezone_display': timezone_display,
        'warning_threshold_days': warning_threshold,
        'whois_api_key': whois_api_key
    }

    return render_template('app_settings.html',
                          settings=combined_settings,
                          data_dir=DATA_DIR,
                          config_file=CONFIG_FILE,
                          current_org=current_org)

@app.route('/backup_config')
def backup_config():
    """Download a backup of the current configuration"""
    if not os.path.exists(CONFIG_FILE):
        flash('No configuration file found to backup', 'error')
        return redirect(url_for('app_settings'))

    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return send_file(CONFIG_FILE,
                    mimetype='application/x-yaml',
                    as_attachment=True,
                    download_name=f'certifly_backup_{timestamp}.yaml')

@app.route('/clear_whois_cache')
@auth.login_required
def clear_whois_cache():
    """Clear the WHOIS cache and domain expiry cache"""
    try:
        # Clear all WHOIS cache entries from database
        db.clear_cache_by_prefix('whois_')

        # Clear domain expiry cache
        global DOMAIN_EXPIRY_CACHE
        DOMAIN_EXPIRY_CACHE = {}

        # Remove the cache file if it exists
        cache_file = os.path.join(DATA_DIR, "domain_expiry_cache.json")
        if os.path.exists(cache_file):
            try:
                os.remove(cache_file)
                logger.info("Domain expiry cache file removed")
            except OSError as e:
                logger.error(f"Error removing domain expiry cache file: {e}")

        # Check if WHOIS API key is configured
        api_key = get_whois_api_key()
        if not api_key:
            flash('Warning: No WHOIS API key configured. Please add a WHOIS API key in settings.', 'warning')
        else:
            flash('WHOIS and domain expiry caches cleared successfully', 'success')
    except Exception as e:
        flash(f'Error clearing caches: {str(e)}', 'error')

    return redirect(url_for('app_settings'))

@app.route('/test_whois_api')
@auth.login_required
def test_whois_api():
    """Test the WHOIS API configuration"""
    api_key = get_whois_api_key()
    if not api_key:
        flash('No WHOIS API key configured. Please add a WHOIS API key in settings.', 'error')
        return redirect(url_for('app_settings'))

    # Test the API with a known domain
    test_domain = "google.com"
    try:
        url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={api_key}&domainName={test_domain}&outputFormat=json"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json()
        if 'WhoisRecord' in data:
            flash(f'WHOIS API test successful! API key is working correctly.', 'success')
        else:
            flash(f'WHOIS API test failed. Received unexpected response: {data}', 'error')
    except Exception as e:
        flash(f'WHOIS API test failed: {str(e)}', 'error')

    return redirect(url_for('app_settings'))

# Reports functionality
@app.route('/reports')
@auth.login_required
def reports():
    """Reports page"""
    # Get current user
    user = auth.get_current_user()

    # Get all organizations the user has access to
    organizations = []
    if user.get('is_admin'):
        organizations = db.get_all_organizations()
    else:
        organizations = db.get_user_organizations(user.get('id'))

    # Get all domains the user has access to
    domains = []
    current_org = user.get('current_organization')
    if current_org:
        domains = db.get_domains_by_organization(current_org.get('id'))

    return render_template('reports.html',
                          organizations=organizations,
                          domains=domains)

@app.route('/generate_report', methods=['POST'])
@auth.login_required
def generate_report():
    """Generate a report based on form data"""
    # Get current user
    user = auth.get_current_user()

    # Get form data
    report_type = request.form.get('report_type', 'all_domains')
    time_range = int(request.form.get('time_range', 30))
    organization_id = request.form.get('organization_id', 'all')
    domain_ids = request.form.getlist('domain_ids')

    # Get status filters
    ssl_statuses = request.form.getlist('ssl_status[]') or ['valid', 'warning', 'expired', 'error']
    domain_statuses = request.form.getlist('domain_status[]') or ['valid', 'warning', 'expired', 'error']
    ping_statuses = request.form.getlist('ping_status[]') or ['up', 'down', 'unknown']

    # Get include options
    include_charts = request.form.get('include_charts') != 'off'  # Default to true if not specified
    include_tables = request.form.get('include_tables') != 'off'  # Default to true if not specified
    include_alerts = request.form.get('include_alerts') != 'off'  # Default to true if not specified

    # Get domains based on selection
    domains = []
    if organization_id == 'all':
        # Get all domains the user has access to
        if user.get('is_admin'):
            domains = db.get_all_domains()
        else:
            # Get domains from all organizations the user belongs to
            user_orgs = db.get_user_organizations(user.get('id'))
            for org in user_orgs:
                domains.extend(db.get_domains_by_organization(org.get('id')))
    else:
        # Get domains for the selected organization
        domains = db.get_domains_by_organization(organization_id)

    # Filter domains if specific ones were selected
    if domain_ids and 'all' not in domain_ids:
        domains = [d for d in domains if str(d.id) in domain_ids]

    # Generate report data based on report type
    report_data = {}

    if report_type == 'ssl_status':
        report_data = generate_ssl_report(domains, time_range, ssl_statuses, include_charts, include_tables, include_alerts)
    elif report_type == 'domain_expiry':
        report_data = generate_domain_expiry_report(domains, time_range, domain_statuses, include_charts, include_tables, include_alerts)
    elif report_type == 'ping_uptime':
        report_data = generate_ping_report(domains, time_range, ping_statuses, include_charts, include_tables, include_alerts)
    else:  # all_domains
        report_data = generate_all_domains_report(domains, time_range, include_charts, include_tables, include_alerts)

    # Return JSON response
    return jsonify(report_data)

@app.route('/export_report', methods=['POST'])
@auth.login_required
def export_report():
    """Export a report in the specified format"""
    # Get current user
    user = auth.get_current_user()

    # Get form data
    report_type = request.form.get('report_type', 'all_domains')
    time_range = int(request.form.get('time_range', 30))
    organization_id = request.form.get('organization_id', 'all')
    domain_ids = request.form.getlist('domain_ids')
    export_format = request.form.get('export_format', 'csv')

    # Get status filters
    ssl_statuses = request.form.getlist('ssl_status[]') or ['valid', 'warning', 'expired', 'error']
    domain_statuses = request.form.getlist('domain_status[]') or ['valid', 'warning', 'expired', 'error']
    ping_statuses = request.form.getlist('ping_status[]') or ['up', 'down', 'unknown']

    # Get include options
    include_charts = request.form.get('include_charts') != 'off'  # Default to true if not specified
    include_tables = request.form.get('include_tables') != 'off'  # Default to true if not specified
    include_alerts = request.form.get('include_alerts') != 'off'  # Default to true if not specified

    # Get domains based on selection (same logic as generate_report)
    domains = []
    if organization_id == 'all':
        if user.get('is_admin'):
            domains = db.get_all_domains()
        else:
            user_orgs = db.get_user_organizations(user.get('id'))
            for org in user_orgs:
                domains.extend(db.get_domains_by_organization(org.get('id')))
    else:
        domains = db.get_domains_by_organization(organization_id)

    # Filter domains if specific ones were selected
    if domain_ids and 'all' not in domain_ids:
        domains = [d for d in domains if str(d.id) in domain_ids]

    # Generate report data
    if report_type == 'ssl_status':
        report_data = generate_ssl_report(domains, time_range, ssl_statuses, include_charts, include_tables, include_alerts)
    elif report_type == 'domain_expiry':
        report_data = generate_domain_expiry_report(domains, time_range, domain_statuses, include_charts, include_tables, include_alerts)
    elif report_type == 'ping_uptime':
        report_data = generate_ping_report(domains, time_range, ping_statuses, include_charts, include_tables, include_alerts)
    else:  # all_domains
        report_data = generate_all_domains_report(domains, time_range, include_charts, include_tables, include_alerts)

    # Export the report in the specified format
    if export_format == 'csv':
        return export_report_csv(report_data)
    elif export_format == 'pdf':
        return export_report_pdf(report_data)
    elif export_format == 'excel':
        return export_report_excel(report_data)
    else:
        flash('Invalid export format', 'error')
        return redirect(url_for('reports'))

# Helper functions for report generation
def generate_ssl_report(domains, time_range, status_filters=None, include_charts=True, include_tables=True, include_alerts=True):
    """Generate SSL certificate status report"""
    # Set default status filters if not provided
    if status_filters is None:
        status_filters = ['valid', 'warning', 'expired', 'error']

    # Get SSL certificate status for each domain
    ssl_statuses = []
    for domain in domains:
        try:
            # Handle both object and dictionary access
            domain_name = domain.get('name') if isinstance(domain, dict) else domain.name
            ssl_status = check_certificate(domain_name)
            # Only include domains with statuses in the filter
            if ssl_status.status in status_filters:
                ssl_statuses.append(ssl_status)
        except Exception as e:
            domain_name = domain.get('name') if isinstance(domain, dict) else getattr(domain, 'name', 'unknown')
            logger.error(f"Error checking SSL for {domain_name}: {str(e)}")

    # Count domains by status
    valid_count = sum(1 for s in ssl_statuses if s.status == 'valid')
    warning_count = sum(1 for s in ssl_statuses if s.status == 'warning')
    expired_count = sum(1 for s in ssl_statuses if s.status == 'expired')
    error_count = sum(1 for s in ssl_statuses if s.status == 'error')

    # Create table data if tables are included
    table_data = []
    if include_tables:
        for status in ssl_statuses:
            table_data.append({
                'Domain': status.domain,
                'Status': status.status.capitalize(),
                'Expiry Date': status.expiry_date.strftime('%Y-%m-%d') if status.expiry_date else 'Unknown',
                'Days Remaining': str(status.days_remaining) if status.days_remaining >= 0 else 'Expired' if status.days_remaining < 0 else 'Unknown'
            })

    # Get alerts related to SSL certificates if alerts are included
    alerts_data = []
    if include_alerts:
        alerts = db.get_alerts_by_type('ssl_certificate', time_range)
        for alert in alerts:
            alerts_data.append({
                'Date': alert['created_at'].strftime('%Y-%m-%d %H:%M'),
                'Domain': alert['domain'],
                'Alert Type': 'SSL Certificate',
                'Message': alert['message'],
                'Status': 'Acknowledged' if alert['acknowledged'] else 'Active'
            })

    # Create chart data if charts are included
    status_chart = {}
    trend_chart = {}
    if include_charts:
        status_chart = {
            'labels': ['Valid', 'Warning', 'Expired', 'Error'],
            'values': [valid_count, warning_count, expired_count, error_count]
        }

        # Create trend data (mock data for now)
        # In a real implementation, this would use historical data from the database
        trend_chart = {
            'labels': [f'Day {i}' for i in range(1, time_range + 1)],
            'datasets': [
                {
                    'label': 'Valid',
                    'data': [valid_count] * time_range,
                    'borderColor': '#28a745',
                    'backgroundColor': 'rgba(40, 167, 69, 0.1)'
                },
                {
                    'label': 'Warning',
                    'data': [warning_count] * time_range,
                    'borderColor': '#ffc107',
                    'backgroundColor': 'rgba(255, 193, 7, 0.1)'
                },
                {
                    'label': 'Expired',
                    'data': [expired_count] * time_range,
                    'borderColor': '#dc3545',
                    'backgroundColor': 'rgba(220, 53, 69, 0.1)'
                }
            ]
        }

    # Return the complete report data
    return {
        'title': 'SSL Certificate Status Report',
        'summary': {
            'total': len(ssl_statuses),
            'healthy': valid_count,
            'warning': warning_count,
            'critical': expired_count + error_count
        },
        'charts': {
            'status': status_chart,
            'trend': trend_chart
        },
        'table': table_data,
        'alerts': alerts_data
    }

def generate_domain_expiry_report(domains, time_range, status_filters=None, include_charts=True, include_tables=True, include_alerts=True):
    """Generate domain expiry status report"""
    # Set default status filters if not provided
    if status_filters is None:
        status_filters = ['valid', 'warning', 'expired', 'error']

    # Get domain expiry status for each domain
    domain_statuses = []
    for domain in domains:
        try:
            # Handle both object and dictionary access
            domain_name = domain.get('name') if isinstance(domain, dict) else domain.name
            domain_status = check_domain_expiry(domain_name)
            # Only include domains with statuses in the filter
            if domain_status.status in status_filters:
                domain_statuses.append(domain_status)
        except Exception as e:
            domain_name = domain.get('name') if isinstance(domain, dict) else getattr(domain, 'name', 'unknown')
            logger.error(f"Error checking domain expiry for {domain_name}: {str(e)}")

    # Count domains by status
    valid_count = sum(1 for s in domain_statuses if s.status == 'valid')
    warning_count = sum(1 for s in domain_statuses if s.status == 'warning')
    expired_count = sum(1 for s in domain_statuses if s.status == 'expired')
    error_count = sum(1 for s in domain_statuses if s.status == 'error')

    # Create table data if tables are included
    table_data = []
    if include_tables:
        for status in domain_statuses:
            table_data.append({
                'Domain': status.name,
                'Status': status.status.capitalize(),
                'Expiry Date': status.expiry_date.strftime('%Y-%m-%d') if status.expiry_date else 'Unknown',
                'Days Remaining': str(status.days_remaining) if status.days_remaining >= 0 else 'Expired' if status.days_remaining < 0 else 'Unknown',
                'Registrar': status.registrar
            })

    # Get alerts related to domain expiry if alerts are included
    alerts_data = []
    if include_alerts:
        alerts = db.get_alerts_by_type('domain_expiry', time_range)
        for alert in alerts:
            alerts_data.append({
                'Date': alert['created_at'].strftime('%Y-%m-%d %H:%M'),
                'Domain': alert['domain'],
                'Alert Type': 'Domain Expiry',
                'Message': alert['message'],
                'Status': 'Acknowledged' if alert['acknowledged'] else 'Active'
            })

    # Create chart data if charts are included
    status_chart = {}
    trend_chart = {}
    if include_charts:
        status_chart = {
            'labels': ['Valid', 'Warning', 'Expired', 'Error'],
            'values': [valid_count, warning_count, expired_count, error_count]
        }

        # Create trend data (mock data for now)
        trend_chart = {
            'labels': [f'Day {i}' for i in range(1, time_range + 1)],
            'datasets': [
                {
                    'label': 'Valid',
                    'data': [valid_count] * time_range,
                    'borderColor': '#28a745',
                    'backgroundColor': 'rgba(40, 167, 69, 0.1)'
                },
                {
                    'label': 'Warning',
                    'data': [warning_count] * time_range,
                    'borderColor': '#ffc107',
                    'backgroundColor': 'rgba(255, 193, 7, 0.1)'
                },
                {
                    'label': 'Expired',
                    'data': [expired_count] * time_range,
                    'borderColor': '#dc3545',
                    'backgroundColor': 'rgba(220, 53, 69, 0.1)'
                }
            ]
        }

    # Return the complete report data
    return {
        'title': 'Domain Expiry Status Report',
        'summary': {
            'total': len(domain_statuses),
            'healthy': valid_count,
            'warning': warning_count,
            'critical': expired_count + error_count
        },
        'charts': {
            'status': status_chart,
            'trend': trend_chart
        },
        'table': table_data,
        'alerts': alerts_data
    }

def generate_ping_report(domains, time_range, status_filters=None, include_charts=True, include_tables=True, include_alerts=True):
    """Generate ping uptime report"""
    # Set default status filters if not provided
    if status_filters is None:
        status_filters = ['up', 'down', 'unknown']

    # Get ping status for each domain
    ping_statuses = []
    for domain in domains:
        try:
            # Handle both object and dictionary access
            domain_name = domain.get('name') if isinstance(domain, dict) else domain.name
            ping_result = check_ping(domain_name)
            # Only include domains with statuses in the filter
            if ping_result['status'] in status_filters:
                ping_statuses.append({
                    'domain': domain_name,
                    'status': ping_result['status'],
                    'response_time': ping_result.get('response_time', 0)
                })
        except Exception as e:
            domain_name = domain.get('name') if isinstance(domain, dict) else getattr(domain, 'name', 'unknown')
            logger.error(f"Error checking ping for {domain_name}: {str(e)}")
            if 'unknown' in status_filters:
                ping_statuses.append({
                    'domain': domain_name,
                    'status': 'unknown',
                    'response_time': 0
                })

    # Count domains by status
    up_count = sum(1 for s in ping_statuses if s['status'] == 'up')
    down_count = sum(1 for s in ping_statuses if s['status'] == 'down')
    unknown_count = sum(1 for s in ping_statuses if s['status'] == 'unknown')

    # Create table data if tables are included
    table_data = []
    if include_tables:
        for status in ping_statuses:
            table_data.append({
                'Domain': status['domain'],
                'Status': status['status'].capitalize(),
                'Response Time': f"{status['response_time']} ms" if status['response_time'] > 0 else 'N/A',
                'Last Checked': datetime.now().strftime('%Y-%m-%d %H:%M')
            })

    # Get alerts related to ping monitoring if alerts are included
    alerts_data = []
    if include_alerts:
        alerts = db.get_alerts_by_type('ping', time_range)
        for alert in alerts:
            alerts_data.append({
                'Date': alert['created_at'].strftime('%Y-%m-%d %H:%M'),
                'Domain': alert['domain'],
                'Alert Type': 'Ping Monitoring',
                'Message': alert['message'],
                'Status': 'Acknowledged' if alert['acknowledged'] else 'Active'
            })

    # Create chart data if charts are included
    status_chart = {}
    trend_chart = {}
    if include_charts:
        status_chart = {
            'labels': ['Up', 'Down', 'Unknown'],
            'values': [up_count, down_count, unknown_count]
        }

        # Create trend data (mock data for now)
        trend_chart = {
            'labels': [f'Day {i}' for i in range(1, time_range + 1)],
            'datasets': [
                {
                    'label': 'Uptime %',
                    'data': [round((up_count / len(ping_statuses)) * 100) if len(ping_statuses) > 0 else 0] * time_range,
                    'borderColor': '#28a745',
                    'backgroundColor': 'rgba(40, 167, 69, 0.1)'
                }
            ]
        }

    # Return the complete report data
    return {
        'title': 'Ping Uptime Report',
        'summary': {
            'total': len(ping_statuses),
            'healthy': up_count,
            'warning': unknown_count,
            'critical': down_count
        },
        'charts': {
            'status': status_chart,
            'trend': trend_chart
        },
        'table': table_data,
        'alerts': alerts_data
    }

def generate_all_domains_report(domains, time_range, include_charts=True, include_tables=True, include_alerts=True):
    """Generate comprehensive report for all domains"""
    # Get status for each domain
    domain_data = []
    for domain in domains:
        try:
            # Handle both object and dictionary access
            domain_name = domain.get('name') if isinstance(domain, dict) else domain.name
            ssl_status = check_certificate(domain_name)
            domain_expiry = check_domain_expiry(domain_name)
            ping_result = check_ping(domain_name)

            # Determine overall status
            if ssl_status.status == 'expired' or domain_expiry.status == 'expired' or ping_result['status'] == 'down':
                overall_status = 'critical'
            elif ssl_status.status == 'warning' or domain_expiry.status == 'warning':
                overall_status = 'warning'
            elif ssl_status.status == 'error' or domain_expiry.status == 'error' or ping_result['status'] == 'unknown':
                overall_status = 'warning'
            else:
                overall_status = 'healthy'

            domain_data.append({
                'domain': domain_name,
                'ssl_status': ssl_status,
                'domain_expiry': domain_expiry,
                'ping_status': ping_result,
                'overall_status': overall_status
            })
        except Exception as e:
            domain_name = domain.get('name') if isinstance(domain, dict) else getattr(domain, 'name', 'unknown')
            logger.error(f"Error checking domain {domain_name}: {str(e)}")

    # Count domains by overall status
    healthy_count = sum(1 for d in domain_data if d['overall_status'] == 'healthy')
    warning_count = sum(1 for d in domain_data if d['overall_status'] == 'warning')
    critical_count = sum(1 for d in domain_data if d['overall_status'] == 'critical')

    # Create table data if tables are included
    table_data = []
    if include_tables:
        for data in domain_data:
            ssl_days = data['ssl_status'].days_remaining if data['ssl_status'].days_remaining >= 0 else 'Expired'
            domain_days = data['domain_expiry'].days_remaining if data['domain_expiry'].days_remaining >= 0 else 'Expired'

            table_data.append({
                'Domain': data['domain'],
                'Status': data['overall_status'].capitalize(),
                'SSL Expiry': f"{ssl_days} days" if isinstance(ssl_days, int) else ssl_days,
                'Domain Expiry': f"{domain_days} days" if isinstance(domain_days, int) else domain_days,
                'Ping Status': data['ping_status']['status'].capitalize()
            })

    # Get all alerts if alerts are included
    alerts_data = []
    if include_alerts:
        alerts = db.get_alerts(time_range)
        for alert in alerts:
            alerts_data.append({
                'Date': alert['created_at'].strftime('%Y-%m-%d %H:%M'),
                'Domain': alert['domain'],
                'Alert Type': alert['alert_type'].replace('_', ' ').title(),
                'Message': alert['message'],
                'Status': 'Acknowledged' if alert['acknowledged'] else 'Active'
            })

    # Create chart data if charts are included
    status_chart = {}
    trend_chart = {}
    if include_charts:
        status_chart = {
            'labels': ['Healthy', 'Warning', 'Critical'],
            'values': [healthy_count, warning_count, critical_count]
        }

        # Create trend data (mock data for now)
        trend_chart = {
            'labels': [f'Day {i}' for i in range(1, time_range + 1)],
            'datasets': [
                {
                    'label': 'Healthy',
                    'data': [healthy_count] * time_range,
                    'borderColor': '#28a745',
                    'backgroundColor': 'rgba(40, 167, 69, 0.1)'
                },
                {
                    'label': 'Warning',
                    'data': [warning_count] * time_range,
                    'borderColor': '#ffc107',
                    'backgroundColor': 'rgba(255, 193, 7, 0.1)'
                },
                {
                    'label': 'Critical',
                    'data': [critical_count] * time_range,
                    'borderColor': '#dc3545',
                    'backgroundColor': 'rgba(220, 53, 69, 0.1)'
                }
            ]
        }

    # Return the complete report data
    return {
        'title': 'All Domains Status Report',
        'summary': {
            'total': len(domain_data),
            'healthy': healthy_count,
            'warning': warning_count,
            'critical': critical_count
        },
        'charts': {
            'status': status_chart,
            'trend': trend_chart
        },
        'table': table_data,
        'alerts': alerts_data
    }

def export_report_csv(report_data):
    """Export report as CSV file"""
    # Create CSV content
    output = io.StringIO()
    writer = csv.writer(output)

    # Write header
    writer.writerow(['Report: ' + report_data['title']])
    writer.writerow(['Generated: ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')])
    writer.writerow([])

    # Write summary
    writer.writerow(['Summary'])
    writer.writerow(['Total Domains', report_data['summary']['total']])
    writer.writerow(['Healthy', report_data['summary']['healthy']])
    writer.writerow(['Warning', report_data['summary']['warning']])
    writer.writerow(['Critical', report_data['summary']['critical']])
    writer.writerow([])

    # Write table data
    if report_data['table']:
        writer.writerow(report_data['table'][0].keys())
        for row in report_data['table']:
            writer.writerow(row.values())

    # Create response
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={report_data['title'].replace(' ', '_')}.csv"}
    )

def export_report_excel(report_data):
    """Export report as Excel file"""
    # For simplicity, we'll just return the CSV for now
    # In a real implementation, this would use a library like openpyxl to create Excel files
    return export_report_csv(report_data)

def export_report_pdf(report_data):
    """Export report as PDF file"""
    # For simplicity, we'll just return the CSV for now
    # In a real implementation, this would use a library like ReportLab or WeasyPrint to create PDF files
    return export_report_csv(report_data)

@app.route('/restore_config', methods=['POST'])
def restore_config():
    """Restore configuration from a backup file"""
    if 'backup_file' not in request.files:
        flash('No backup file provided', 'error')
        return redirect(url_for('app_settings'))

    backup_file = request.files['backup_file']
    if backup_file.filename == '':
        flash('No backup file selected', 'error')
        return redirect(url_for('app_settings'))

    # Validate YAML format
    try:
        backup_content = backup_file.read()
        backup_file.seek(0)  # Reset file pointer
        yaml_content = yaml.safe_load(backup_content)

        if not isinstance(yaml_content, dict):
            flash('Invalid backup file format', 'error')
            return redirect(url_for('app_settings'))

        # Create a backup of the current config before restoring
        if os.path.exists(CONFIG_FILE):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            pre_restore_backup = os.path.join(DATA_DIR, f"config_pre_restore_{timestamp}.yaml")
            shutil.copy2(CONFIG_FILE, pre_restore_backup)

        # Save the uploaded file as the new config
        backup_file.save(CONFIG_FILE)
        flash('Configuration restored successfully', 'success')
    except Exception as e:
        flash(f'Error restoring backup: {str(e)}', 'error')

    return redirect(url_for('app_settings'))

@app.route('/add_ssl_from_dashboard', methods=['POST'])
def add_ssl_from_dashboard():
    """Add a new domain to SSL certificate monitoring from the dashboard"""
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()

        if not domain:
            flash('Please enter a domain name', 'error')
            return redirect(url_for('index'))

        # Clean the domain
        domain = clean_domain_name(domain)
        if not domain:
            flash('Invalid domain format', 'error')
            return redirect(url_for('index'))

        # Check if domain already exists
        config = load_config()
        if 'ssl_domains' not in config:
            config['ssl_domains'] = []

        for entry in config.get('ssl_domains', []):
            if entry.get('url') == domain:
                flash(f'Domain {domain} is already being monitored for SSL', 'error')
                return redirect(url_for('index'))

        # Add domain to config
        config['ssl_domains'].append({'url': domain})
        save_config(config)

        flash(f'Domain {domain} added to SSL monitoring successfully', 'success')
        return redirect(url_for('index'))

@app.route('/add_domain_from_dashboard', methods=['POST'])
def add_domain_from_dashboard():
    """Add a new domain to monitoring from the dashboard"""
    if request.method == 'POST':
        domain = request.form.get('domain', '').strip()
        monitor_ssl = 'monitor_ssl' in request.form
        monitor_expiry = 'monitor_expiry' in request.form
        monitor_ping = 'monitor_ping' in request.form

        if not domain:
            flash('Please enter a domain name', 'error')
            return redirect(url_for('index'))

        # Clean the domain
        domain = clean_domain_name(domain)
        if not domain:
            flash('Invalid domain format', 'error')
            return redirect(url_for('index'))

        # Check if at least one monitoring option is selected
        if not any([monitor_ssl, monitor_expiry, monitor_ping]):
            flash('Please select at least one monitoring option', 'error')
            return redirect(url_for('index'))

        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            flash("You don't have access to any organizations", 'error')
            return redirect(url_for('profile'))

        # Load the current configuration
        config = load_config()

        # Initialize config sections if they don't exist
        if 'ssl_domains' not in config:
            config['ssl_domains'] = []
        if 'domain_expiry' not in config:
            config['domain_expiry'] = []
        if 'ping_hosts' not in config:
            config['ping_hosts'] = []

        # Check if domain already exists in this organization
        existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
        if existing_domain:
            # Update existing domain with new monitoring options
            ssl_monitored = monitor_ssl or existing_domain['ssl_monitored']
            expiry_monitored = monitor_expiry or existing_domain['expiry_monitored']
            ping_monitored = monitor_ping or existing_domain['ping_monitored']

            updated = db.update_domain(
                existing_domain['id'],
                domain,
                ssl_monitored,
                expiry_monitored,
                ping_monitored
            )
            if updated:
                # Update the configuration file

                # Update SSL monitoring
                if ssl_monitored:
                    # Check if domain is already in ssl_domains
                    ssl_exists = False
                    for entry in config['ssl_domains']:
                        if entry.get('url') == domain:
                            ssl_exists = True
                            break

                    # Add to ssl_domains if not already there
                    if not ssl_exists:
                        config['ssl_domains'].append({'url': domain})
                else:
                    # Remove from SSL domains if monitoring is disabled
                    config['ssl_domains'] = [entry for entry in config['ssl_domains']
                                           if entry.get('url') != domain]

                # Update domain expiry monitoring
                if expiry_monitored:
                    # Check if domain is already in domain_expiry
                    expiry_exists = False
                    for entry in config['domain_expiry']:
                        if entry.get('name') == domain:
                            expiry_exists = True
                            break

                    # Add to domain_expiry if not already there
                    if not expiry_exists:
                        config['domain_expiry'].append({'name': domain})
                else:
                    # Remove from domain expiry if monitoring is disabled
                    config['domain_expiry'] = [entry for entry in config['domain_expiry']
                                             if entry.get('name') != domain]

                # Update ping monitoring
                if ping_monitored:
                    # Check if domain is already in ping_hosts
                    ping_exists = False
                    for entry in config['ping_hosts']:
                        if entry.get('host') == domain:
                            ping_exists = True
                            break

                    # Add to ping_hosts if not already there
                    if not ping_exists:
                        config['ping_hosts'].append({'host': domain})
                else:
                    # Remove from ping hosts if monitoring is disabled
                    config['ping_hosts'] = [entry for entry in config['ping_hosts']
                                          if entry.get('host') != domain]

                # Save the updated configuration
                save_config(config)

                flash(f'Domain {domain} monitoring options updated successfully', 'success')
            else:
                flash(f'Error updating domain {domain}', 'error')
        else:
            # Add new domain with selected monitoring options
            domain_id = db.add_domain(domain, current_org['id'], monitor_ssl, monitor_expiry, monitor_ping)
            if domain_id:
                # Update the configuration file
                config_updated = False

                # Add to SSL monitoring
                if monitor_ssl:
                    # Check if domain is already in ssl_domains
                    ssl_exists = False
                    for entry in config['ssl_domains']:
                        if entry.get('url') == domain:
                            ssl_exists = True
                            break

                    # Add to ssl_domains if not already there
                    if not ssl_exists:
                        config['ssl_domains'].append({'url': domain})
                        config_updated = True

                        # Force an immediate check to populate the SSL cache
                        try:
                            # Clear any existing cache entry
                            if domain in SSL_CACHE:
                                del SSL_CACHE[domain]

                            # Perform a check to populate the cache
                            check_certificate(domain)
                        except Exception as e:
                            logger.error(f"Error checking SSL for {domain}: {str(e)}")

                # Add to domain expiry monitoring
                if monitor_expiry:
                    # Check if domain is already in domain_expiry
                    expiry_exists = False
                    for entry in config['domain_expiry']:
                        if entry.get('name') == domain:
                            expiry_exists = True
                            break

                    # Add to domain_expiry if not already there
                    if not expiry_exists:
                        config['domain_expiry'].append({'name': domain})
                        config_updated = True

                        # Force an immediate check to populate the domain expiry cache
                        try:
                            # Clear any existing cache entry
                            if domain in DOMAIN_EXPIRY_CACHE:
                                del DOMAIN_EXPIRY_CACHE[domain]

                            # Perform a check to populate the cache
                            check_domain_expiry(domain)
                        except Exception as e:
                            logger.error(f"Error checking domain expiry for {domain}: {str(e)}")

                # Add to ping monitoring
                if monitor_ping:
                    # Check if domain is already in ping_hosts
                    ping_exists = False
                    for entry in config['ping_hosts']:
                        if entry.get('host') == domain:
                            ping_exists = True
                            break

                    # Add to ping_hosts if not already there
                    if not ping_exists:
                        config['ping_hosts'].append({'host': domain})
                        config_updated = True

                        # Force an immediate ping check
                        try:
                            # Clear any existing cache entry
                            if domain in PING_CACHE:
                                del PING_CACHE[domain]

                            # Perform a check to populate the cache
                            check_ping(domain)
                        except Exception as e:
                            logger.error(f"Error checking ping for {domain}: {str(e)}")

                # Save the updated configuration if changes were made
                if config_updated:
                    save_config(config)

                # Track what was added
                added_to = []
                if monitor_ssl:
                    added_to.append('SSL certificates')
                if monitor_expiry:
                    added_to.append('domain expiry')
                if monitor_ping:
                    added_to.append('ping monitoring')

                flash(f'Domain {domain} added to {", ".join(added_to)} successfully!', 'success')
            else:
                flash(f'Error adding domain {domain}', 'error')

        return redirect(url_for('index'))

@app.route('/bulk_add_domains_from_dashboard', methods=['POST'])
def bulk_add_domains_from_dashboard():
    """Add multiple domains to monitoring from the dashboard"""
    if request.method == 'POST':
        domains_text = request.form.get('domains', '').strip()
        monitor_ssl = 'monitor_ssl' in request.form
        monitor_expiry = 'monitor_expiry' in request.form
        monitor_ping = 'monitor_ping' in request.form

        if not domains_text:
            flash('Please enter at least one domain', 'error')
            return redirect(url_for('index'))

        # Check if at least one monitoring option is selected
        if not any([monitor_ssl, monitor_expiry, monitor_ping]):
            flash('Please select at least one monitoring option', 'error')
            return redirect(url_for('index'))

        # Split by newlines, commas, or spaces
        domains = re.split(r'[\n,\s]+', domains_text)
        domains = [d.strip() for d in domains if d.strip()]

        if not domains:
            flash('No valid domains found', 'error')
            return redirect(url_for('index'))

        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            flash("You don't have access to any organizations", 'error')
            return redirect(url_for('profile'))

        # Load the current configuration
        config = load_config()

        # Initialize config sections if they don't exist
        if 'ssl_domains' not in config:
            config['ssl_domains'] = []
        if 'domain_expiry' not in config:
            config['domain_expiry'] = []
        if 'ping_hosts' not in config:
            config['ping_hosts'] = []

        added_count = 0
        updated_count = 0
        skipped_count = 0

        # Track domains added to config
        ssl_domains_added = []
        expiry_domains_added = []
        ping_hosts_added = []

        for domain in domains:
            # Clean the domain
            domain = clean_domain_name(domain)
            if not domain:
                skipped_count += 1
                continue

            # Check if domain already exists in this organization
            existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
            if existing_domain:
                # Update existing domain with new monitoring options
                updated = db.update_domain(
                    existing_domain['id'],
                    domain,
                    monitor_ssl or existing_domain['ssl_monitored'],
                    monitor_expiry or existing_domain['expiry_monitored'],
                    monitor_ping or existing_domain['ping_monitored']
                )
                if updated:
                    updated_count += 1

                    # Update SSL monitoring in config
                    if monitor_ssl and not existing_domain['ssl_monitored']:
                        ssl_domains_added.append(domain)

                    # Update domain expiry monitoring in config
                    if monitor_expiry and not existing_domain['expiry_monitored']:
                        expiry_domains_added.append(domain)

                    # Update ping monitoring in config
                    if monitor_ping and not existing_domain['ping_monitored']:
                        ping_hosts_added.append(domain)
                else:
                    skipped_count += 1
            else:
                # Add new domain with selected monitoring options
                domain_id = db.add_domain(domain, current_org['id'], monitor_ssl, monitor_expiry, monitor_ping)
                if domain_id:
                    added_count += 1

                    # Add to config lists
                    if monitor_ssl:
                        # Check if domain is already in ssl_domains
                        ssl_exists = False
                        for entry in config['ssl_domains']:
                            if entry.get('url') == domain:
                                ssl_exists = True
                                break

                        # Add to ssl_domains_added if not already in config
                        if not ssl_exists:
                            ssl_domains_added.append(domain)

                            # Force an immediate check to populate the SSL cache
                            try:
                                # Clear any existing cache entry
                                if domain in SSL_CACHE:
                                    del SSL_CACHE[domain]

                                # Perform a check to populate the cache
                                check_certificate(domain)
                            except Exception as e:
                                logger.error(f"Error checking SSL for {domain}: {str(e)}")

                    if monitor_expiry:
                        # Check if domain is already in domain_expiry
                        expiry_exists = False
                        for entry in config['domain_expiry']:
                            if entry.get('name') == domain:
                                expiry_exists = True
                                break

                        # Add to expiry_domains_added if not already in config
                        if not expiry_exists:
                            expiry_domains_added.append(domain)

                            # Force an immediate check to populate the domain expiry cache
                            try:
                                # Clear any existing cache entry
                                if domain in DOMAIN_EXPIRY_CACHE:
                                    del DOMAIN_EXPIRY_CACHE[domain]

                                # Perform a check to populate the cache
                                check_domain_expiry(domain)
                            except Exception as e:
                                logger.error(f"Error checking domain expiry for {domain}: {str(e)}")

                    if monitor_ping:
                        # Check if domain is already in ping_hosts
                        ping_exists = False
                        for entry in config['ping_hosts']:
                            if entry.get('host') == domain:
                                ping_exists = True
                                break

                        # Add to ping_hosts_added if not already in config
                        if not ping_exists:
                            ping_hosts_added.append(domain)

                            # Force an immediate ping check
                            try:
                                # Clear any existing cache entry
                                if domain in PING_CACHE:
                                    del PING_CACHE[domain]

                                # Perform a check to populate the cache
                                check_ping(domain)
                            except Exception as e:
                                logger.error(f"Error checking ping for {domain}: {str(e)}")
                else:
                    skipped_count += 1

        # Update the configuration file with all the new domains

        # Add SSL domains to config
        for domain in ssl_domains_added:
            # Check if domain is already in ssl_domains
            ssl_exists = False
            for entry in config['ssl_domains']:
                if entry.get('url') == domain:
                    ssl_exists = True
                    break

            # Add to ssl_domains if not already there
            if not ssl_exists:
                config['ssl_domains'].append({'url': domain})

        # Add domain expiry domains to config
        for domain in expiry_domains_added:
            # Check if domain is already in domain_expiry
            expiry_exists = False
            for entry in config['domain_expiry']:
                if entry.get('name') == domain:
                    expiry_exists = True
                    break

            # Add to domain_expiry if not already there
            if not expiry_exists:
                config['domain_expiry'].append({'name': domain})

        # Add ping hosts to config
        for domain in ping_hosts_added:
            # Check if domain is already in ping_hosts
            ping_exists = False
            for entry in config['ping_hosts']:
                if entry.get('host') == domain:
                    ping_exists = True
                    break

            # Add to ping_hosts if not already there
            if not ping_exists:
                config['ping_hosts'].append({'host': domain})

        # Save the updated configuration if any changes were made
        if ssl_domains_added or expiry_domains_added or ping_hosts_added:
            save_config(config)

        # Create appropriate message
        monitoring_types = []
        if monitor_ssl:
            monitoring_types.append("SSL certificates")
        if monitor_expiry:
            monitoring_types.append("Domain expiry")
        if monitor_ping:
            monitoring_types.append("Ping monitoring")

        monitoring_message = ", ".join(monitoring_types)

        if added_count > 0 or updated_count > 0:
            message = f'Added {added_count} domains'
            if updated_count > 0:
                message += f', updated {updated_count} domains'
            message += f' to {monitoring_message}'
            if skipped_count > 0:
                message += f', skipped {skipped_count} invalid domains'
            flash(message, 'success')
        else:
            flash(f'No domains added or updated, skipped {skipped_count} invalid domains', 'warning')

        return redirect(url_for('index'))

@app.route('/add_ping_from_dashboard', methods=['POST'])
def add_ping_from_dashboard():
    """Add a new host to ping monitoring from the dashboard"""
    if request.method == 'POST':
        host = request.form.get('host', '').strip()

        if not host:
            flash('Please enter a host name or IP address', 'error')
            return redirect(url_for('index'))

        # Clean the host
        host = clean_domain_name(host)
        if not host:
            flash('Invalid host format', 'error')
            return redirect(url_for('index'))

        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            flash("You don't have access to any organizations", 'error')
            return redirect(url_for('profile'))

        # Check if host already exists in this organization
        existing_domain = db.get_domain_by_name_and_org(host, current_org['id'])
        if existing_domain:
            # If domain exists and ping monitoring is not enabled, update it
            if not existing_domain['ping_monitored']:
                db.update_domain(existing_domain['id'], host, existing_domain['ssl_monitored'], existing_domain['expiry_monitored'], True)
                flash(f'Host {host} updated to include ping monitoring', 'success')
            else:
                flash(f'Host {host} is already being monitored for ping', 'error')
        else:
            # Add new domain with ping monitoring enabled
            domain_id = db.add_domain(host, current_org['id'], False, False, True)
            if domain_id:
                flash(f'Host {host} added to ping monitoring successfully', 'success')
            else:
                flash(f'Error adding host {host}', 'error')

        return redirect(url_for('index'))

@app.route('/remove_all_monitors/<domain>')
def remove_all_monitors(domain):
    """Remove all monitoring (SSL, domain expiry, ping) for a domain"""
    if not domain:
        flash('Domain name is required', 'error')
        return redirect(url_for('index'))

    domain = clean_domain_name(domain)

    # Get current user
    current_user = auth.get_current_user()

    # Get current organization
    current_org = current_user.get('current_organization')
    if not current_org:
        flash("You don't have access to any organizations", 'error')
        return redirect(url_for('profile'))

    # Load the current configuration
    config = load_config()

    # Get domain by name and organization
    existing_domain = db.get_domain_by_name_and_org(domain, current_org['id'])
    if existing_domain:
        # Delete the domain from the database
        if db.delete_domain(existing_domain['id']):
            # Remove from SSL domains in config
            if 'ssl_domains' in config:
                config['ssl_domains'] = [entry for entry in config['ssl_domains']
                                        if entry.get('url') != domain]

            # Remove from domain expiry in config
            if 'domain_expiry' in config:
                config['domain_expiry'] = [entry for entry in config['domain_expiry']
                                          if entry.get('name') != domain]

            # Remove from ping hosts in config
            if 'ping_hosts' in config:
                config['ping_hosts'] = [entry for entry in config['ping_hosts']
                                       if entry.get('host') != domain]

            # Save the updated configuration
            save_config(config)

            flash(f'All monitoring for {domain} has been removed', 'success')
        else:
            flash(f'Error removing monitoring for {domain}', 'error')
    else:
        flash(f'Domain {domain} not found', 'error')

    return redirect(url_for('index'))

@app.route('/notifications')
def notifications():
    """Notification settings page"""
    notification_settings = get_notification_settings()
    return render_template('notifications.html', notifications=notification_settings.__dict__)

@app.route('/save_notifications', methods=['POST'])
def save_notifications():
    """Save notification settings"""
    if request.method == 'POST':
        notification_type = request.form.get('notification_type')
        enabled = request.form.get('enabled') == 'true'

        config = load_config()
        if 'notifications' not in config:
            config['notifications'] = {}

        if notification_type == 'email':
            if 'email' not in config['notifications']:
                config['notifications']['email'] = {}

            config['notifications']['email']['enabled'] = enabled
            if enabled:
                config['notifications']['email']['smtp_server'] = request.form.get('smtp_server', '')
                config['notifications']['email']['smtp_port'] = int(request.form.get('smtp_port', 587))
                config['notifications']['email']['smtp_username'] = request.form.get('smtp_username', '')

                # Only update password if provided
                new_password = request.form.get('smtp_password', '')
                if new_password:
                    config['notifications']['email']['smtp_password'] = new_password

                config['notifications']['email']['notification_email'] = request.form.get('notification_email', '')

                # Update warning threshold days
                warning_threshold = request.form.get('warning_threshold_days', '10')
                try:
                    warning_threshold = int(warning_threshold)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid warning_threshold_days value: {warning_threshold}. Using default value of 10.")
                    warning_threshold = 10

                config['notifications']['email']['warning_threshold_days'] = warning_threshold

                # Also update the email_settings for backward compatibility
                if 'email_settings' not in config:
                    config['email_settings'] = {}
                config['email_settings']['warning_threshold_days'] = warning_threshold

            flash('Email notification settings saved successfully', 'success')

        elif notification_type == 'teams':
            if 'teams' not in config['notifications']:
                config['notifications']['teams'] = {}

            config['notifications']['teams']['enabled'] = enabled
            if enabled:
                config['notifications']['teams']['webhook_url'] = request.form.get('webhook_url', '')

            flash('Microsoft Teams notification settings saved successfully', 'success')

        elif notification_type == 'slack':
            if 'slack' not in config['notifications']:
                config['notifications']['slack'] = {}

            config['notifications']['slack']['enabled'] = enabled
            if enabled:
                config['notifications']['slack']['webhook_url'] = request.form.get('webhook_url', '')
                config['notifications']['slack']['channel'] = request.form.get('channel', '')

            flash('Slack notification settings saved successfully', 'success')

        elif notification_type == 'discord':
            if 'discord' not in config['notifications']:
                config['notifications']['discord'] = {}

            config['notifications']['discord']['enabled'] = enabled
            if enabled:
                config['notifications']['discord']['webhook_url'] = request.form.get('webhook_url', '')
                config['notifications']['discord']['username'] = request.form.get('username', 'Certifly Bot')

            flash('Discord notification settings saved successfully', 'success')

        save_config(config)
        return redirect(url_for('notifications'))

    return redirect(url_for('notifications'))

@app.route('/test_notification', methods=['POST'])
def test_notification():
    """Test notification settings"""
    if request.method == 'POST':
        notification_type = request.form.get('notification_type')

        notification_settings = get_notification_settings()
        settings = getattr(notification_settings, notification_type, {})

        success, message = send_test_notification(notification_type, settings)

        if success:
            flash(f'Test notification sent successfully: {message}', 'success')
        else:
            flash(f'Failed to send test notification: {message}', 'error')

        return redirect(url_for('notifications'))

    return redirect(url_for('notifications'))

@app.route('/check_ping/<domain>')
def check_domain_ping(domain):
    """Check ping status for a domain and return JSON response"""
    ping_result = check_ping(domain)

    # Get uptime percentage
    uptime_percentage = db.calculate_uptime_percentage(domain)
    if uptime_percentage is not None:
        uptime_percentage = round(uptime_percentage, 1)

    # Get ping history for uptime segments
    ping_history = db.get_ping_history(domain, hours=12)

    # Create uptime segments (12 segments representing the last 12 hours)
    uptime_segments = []
    if ping_history:
        # Group history into 12 hourly segments
        current_time = datetime.now()

        for i in range(12):
            segment_start = current_time - timedelta(hours=12-i)
            segment_end = current_time - timedelta(hours=11-i)

            # Find all checks in this segment
            segment_checks = [check for check in ping_history
                             if check['checked_at'] and
                             segment_start <= datetime.fromtimestamp(check['checked_at']) < segment_end]

            if segment_checks:
                # If any check is down, the segment is down
                if any(check['status'] == 'down' for check in segment_checks):
                    uptime_segments.append('down')
                else:
                    uptime_segments.append('up')
            else:
                # No checks in this segment
                uptime_segments.append('unknown')
    else:
        # If no history, use current status for all segments
        uptime_segments = [ping_result["status"]] * 12

    # Update ping status in config for ping hosts
    config = load_config()
    ping_hosts = config.get('ping_hosts', [])
    response_history = []

    for ping_host in ping_hosts:
        if ping_host.get('host') == domain:
            # Initialize response history if it doesn't exist
            if 'response_history' not in ping_host:
                ping_host['response_history'] = []

            # Add new response time to history (keep last 20 entries)
            if ping_result["status"] == "up":
                ping_host['response_history'].append(ping_result["response_time"])
                # Keep only the last 20 entries
                ping_host['response_history'] = ping_host['response_history'][-20:]

            response_history = ping_host.get('response_history', [])

            # Save the updated config
            save_config(config)
            break

    # Return response with history and uptime data
    return {
        'domain': domain,
        'ping_status': ping_result["status"],
        'response_time': ping_result["response_time"],
        'response_history': response_history,
        'uptime_percentage': uptime_percentage,
        'uptime_segments': uptime_segments
    }

@app.route('/api/domains/<int:domain_id>', methods=['DELETE'])
def delete_domain(domain_id):
    try:
        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            return jsonify({'success': False, 'error': 'You don\'t have access to any organizations'}), 403

        # Get domain by ID
        domain = db.get_domain_by_id(domain_id)
        if not domain:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        # Check if domain belongs to current organization
        if domain['organization_id'] != current_org['id']:
            return jsonify({'success': False, 'error': 'You don\'t have permission to delete this domain'}), 403

        # Load the current configuration
        config = load_config()

        # Get domain name before deleting
        domain_name = domain['name']

        # Delete domain from database
        if db.delete_domain(domain_id):
            # Remove from SSL domains in config
            if 'ssl_domains' in config:
                config['ssl_domains'] = [entry for entry in config['ssl_domains']
                                        if entry.get('url') != domain_name]

            # Remove from domain expiry in config
            if 'domain_expiry' in config:
                config['domain_expiry'] = [entry for entry in config['domain_expiry']
                                          if entry.get('name') != domain_name]

            # Remove from ping hosts in config
            if 'ping_hosts' in config:
                config['ping_hosts'] = [entry for entry in config['ping_hosts']
                                       if entry.get('host') != domain_name]

            # Save the updated configuration
            save_config(config)

            logger.info(f"Domain {domain_name} (ID: {domain_id}) deleted successfully")
            return jsonify({'success': True, 'message': f'Domain {domain_name} deleted successfully'})
        else:
            return jsonify({'success': False, 'error': 'Failed to delete domain'}), 500
    except Exception as e:
        logger.error(f"Error deleting domain {domain_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

def add_cache_headers(response, max_age=0, private=True, etag=None):
    """Add cache control headers to a response"""
    if private:
        response.cache_control.private = True
    else:
        response.cache_control.public = True

    response.cache_control.max_age = max_age

    if etag:
        response.set_etag(etag)

    return response

@app.route('/api/domains/<int:domain_id>', methods=['GET'])
def get_domain(domain_id):
    try:
        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            return jsonify({'success': False, 'error': 'You don\'t have access to any organizations'}), 403

        # Get domain by ID
        domain = db.get_domain_by_id(domain_id)
        if not domain:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        # Check if domain belongs to current organization
        if domain['organization_id'] != current_org['id']:
            return jsonify({'success': False, 'error': 'You don\'t have permission to view this domain'}), 403

        # Determine which monitoring services are enabled for this domain
        monitors = []
        if domain['ssl_monitored']:
            monitors.append('ssl')
        if domain['expiry_monitored']:
            monitors.append('expiry')
        if domain['ping_monitored']:
            monitors.append('ping')

        # Create response data
        response_data = {
            'success': True,
            'data': {
                'domain': domain['name'],
                'monitors': monitors
            }
        }

        # Generate ETag based on response data
        import hashlib
        etag = hashlib.md5(str(response_data).encode()).hexdigest()

        # Create response with cache headers
        response = jsonify(response_data)
        return add_cache_headers(response, max_age=60, private=True, etag=etag)

    except Exception as e:
        logger.error(f"Error getting domain details: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/edit_domain_from_dashboard', methods=['POST'])
def edit_domain_from_dashboard():
    """Edit domain monitoring settings from the dashboard"""
    if request.method == 'POST':
        domain_id = request.form.get('domain_id')
        domain = request.form.get('domain')
        original_domain = request.form.get('original_domain')
        monitor_ssl = 'monitor_ssl' in request.form
        monitor_expiry = 'monitor_expiry' in request.form
        monitor_ping = 'monitor_ping' in request.form

        if not domain or not domain_id or not original_domain:
            flash('Domain information is missing', 'error')
            return redirect(url_for('index'))

        try:
            domain_id = int(domain_id)
        except ValueError:
            flash('Invalid domain ID', 'error')
            return redirect(url_for('index'))

        # Clean the domain names
        domain = clean_domain_name(domain)
        original_domain = clean_domain_name(original_domain)

        if not domain:
            flash('Invalid domain format', 'error')
            return redirect(url_for('index'))

        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            flash("You don't have access to any organizations", 'error')
            return redirect(url_for('profile'))

        # Load the current configuration
        config = load_config()

        # Initialize config sections if they don't exist
        if 'ssl_domains' not in config:
            config['ssl_domains'] = []
        if 'domain_expiry' not in config:
            config['domain_expiry'] = []
        if 'ping_hosts' not in config:
            config['ping_hosts'] = []

        # Get the domain by ID
        existing_domain = db.get_domain_by_id(domain_id)
        if not existing_domain:
            flash(f'Domain with ID {domain_id} not found', 'error')
            return redirect(url_for('index'))

        # Check if the domain belongs to the current organization
        if existing_domain['organization_id'] != current_org['id']:
            flash("You don't have permission to edit this domain", 'error')
            return redirect(url_for('index'))

        # Check if the new domain name already exists (only if domain name was changed)
        if domain != original_domain:
            # Check if domain already exists in this organization
            domain_exists = db.get_domain_by_name_and_org(domain, current_org['id'])
            if domain_exists:
                flash(f'Domain {domain} is already being monitored. Please use a different name.', 'error')
                return redirect(url_for('index'))

        # Update the domain in the database
        updated = db.update_domain(
            domain_id,
            domain,  # New domain name
            monitor_ssl,
            monitor_expiry,
            monitor_ping
        )

        if updated:
            # Update the configuration file

            # If domain name was changed, remove old domain from config
            if domain != original_domain:
                # Remove old domain from SSL domains
                if 'ssl_domains' in config:
                    config['ssl_domains'] = [entry for entry in config['ssl_domains']
                                            if entry.get('url') != original_domain]

                # Remove old domain from domain expiry
                if 'domain_expiry' in config:
                    config['domain_expiry'] = [entry for entry in config['domain_expiry']
                                              if entry.get('name') != original_domain]

                # Remove old domain from ping hosts
                if 'ping_hosts' in config:
                    config['ping_hosts'] = [entry for entry in config['ping_hosts']
                                           if entry.get('host') != original_domain]

            # Update SSL monitoring
            if monitor_ssl:
                # Check if domain is already in ssl_domains
                ssl_exists = False
                for entry in config['ssl_domains']:
                    if entry.get('url') == domain:
                        ssl_exists = True
                        break

                # Add to ssl_domains if not already there
                if not ssl_exists:
                    config['ssl_domains'].append({'url': domain})
            else:
                # Remove from SSL domains if monitoring is disabled
                config['ssl_domains'] = [entry for entry in config['ssl_domains']
                                        if entry.get('url') != domain]

            # Update domain expiry monitoring
            if monitor_expiry:
                # Check if domain is already in domain_expiry
                expiry_exists = False
                for entry in config['domain_expiry']:
                    if entry.get('name') == domain:
                        expiry_exists = True
                        break

                # Add to domain_expiry if not already there
                if not expiry_exists:
                    config['domain_expiry'].append({'name': domain})
            else:
                # Remove from domain expiry if monitoring is disabled
                config['domain_expiry'] = [entry for entry in config['domain_expiry']
                                          if entry.get('name') != domain]

            # Update ping monitoring
            if monitor_ping:
                # Check if domain is already in ping_hosts
                ping_exists = False
                for entry in config['ping_hosts']:
                    if entry.get('host') == domain:
                        ping_exists = True
                        break

                # Add to ping_hosts if not already there
                if not ping_exists:
                    config['ping_hosts'].append({'host': domain})
            else:
                # Remove from ping hosts if monitoring is disabled
                config['ping_hosts'] = [entry for entry in config['ping_hosts']
                                       if entry.get('host') != domain]

            # Save the updated configuration
            save_config(config)

            # Show appropriate success message based on whether the domain name was changed
            if domain != original_domain:
                flash(f'Domain changed from {original_domain} to {domain} and monitoring settings updated successfully', 'success')
            else:
                flash(f'Domain {domain} monitoring settings updated successfully', 'success')
        else:
            flash(f'Error updating domain {domain}', 'error')

        return redirect(url_for('index'))

@app.route('/api/domains/<int:domain_id>/refresh', methods=['POST'])
def refresh_domain(domain_id):
    try:
        start_time = time.time()
        logger.debug(f"Starting refresh for domain ID {domain_id}")

        # Get current user
        current_user = auth.get_current_user()

        # Get current organization
        current_org = current_user.get('current_organization')
        if not current_org:
            return jsonify({'success': False, 'error': 'You don\'t have access to any organizations'}), 403

        # Get domain by ID
        domain = db.get_domain_by_id(domain_id)
        if not domain:
            return jsonify({'success': False, 'error': 'Domain not found'}), 404

        # Check if domain belongs to current organization
        if domain['organization_id'] != current_org['id']:
            return jsonify({'success': False, 'error': 'You don\'t have permission to refresh this domain'}), 403

        domain_to_refresh = domain['name']

        # Refresh domain data
        domain_data = {}

        # Check if domain is monitored for SSL
        if domain['ssl_monitored']:
            # Clear SSL cache for this domain to force a fresh check
            if domain_to_refresh in SSL_CACHE:
                del SSL_CACHE[domain_to_refresh]
                save_ssl_cache(SSL_CACHE)

            cert_status = check_certificate(domain_to_refresh)
            domain_data['ssl_status'] = {
                'status': cert_status.status,
                'days_remaining': cert_status.days_remaining,
                'expiry_date': cert_status.expiry_date.strftime('%Y-%m-%d')
            }

        # Check if domain is monitored for expiry
        if domain['expiry_monitored']:
            # Clear domain expiry cache for this domain to force a fresh check
            if domain_to_refresh in DOMAIN_EXPIRY_CACHE:
                del DOMAIN_EXPIRY_CACHE[domain_to_refresh]
                save_domain_expiry_cache(DOMAIN_EXPIRY_CACHE)

            domain_status = check_domain_expiry(domain_to_refresh)
            domain_data['domain_status'] = {
                'status': domain_status.status,
                'days_remaining': domain_status.days_remaining,
                'expiry_date': domain_status.expiry_date.strftime('%Y-%m-%d'),
                'registrar': domain_status.registrar
            }

        # Clear ping cache for this domain to force a fresh check
        if domain_to_refresh in PING_CACHE:
            del PING_CACHE[domain_to_refresh]
            save_ping_cache(PING_CACHE)

        # Check ping status
        ping_result = check_ping(domain_to_refresh)
        domain_data['ping_status'] = ping_result

        end_time = time.time()
        logger.info(f"Domain {domain_to_refresh} (ID: {domain_id}) refreshed successfully in {end_time - start_time:.2f} seconds")

        # Create response data
        response_data = {
            'success': True,
            'message': f'Domain {domain_to_refresh} refreshed successfully',
            'data': domain_data,
            'timestamp': int(time.time())
        }

        # Generate ETag based on response data
        import hashlib
        etag = hashlib.md5(str(response_data).encode()).hexdigest()

        # Create response with cache headers - no caching for refresh results
        response = jsonify(response_data)
        return add_cache_headers(response, max_age=0, private=True, etag=etag)
    except Exception as e:
        logger.error(f"Error refreshing domain {domain_id}: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Storage route removed as requested

# Template filters
@app.template_filter('datetime')
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object to a string"""
    if value is None:
        return ""

    # Handle numeric timestamps (stored as int or float)
    if isinstance(value, (int, float)):
        try:
            value = datetime.fromtimestamp(value)
            return value.strftime(format)
        except (ValueError, OverflowError, OSError):
            return str(value)

    # Handle string values
    if isinstance(value, str):
        try:
            # Try to parse as ISO format
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
            return value.strftime(format)
        except ValueError:
            try:
                # Try to parse as timestamp
                value = datetime.fromtimestamp(float(value))
                return value.strftime(format)
            except (ValueError, OverflowError, OSError):
                # If all parsing fails, return the string as is
                return value

    # If it's already a datetime object, format it
    try:
        return value.strftime(format)
    except AttributeError:
        # If all else fails, return as string
        return str(value)



# Organization Routes
@app.route('/organizations')
@auth.login_required
def organizations():
    """Organizations page"""
    user = auth.get_current_user()

    # Get all organizations for admin, or user's organizations for regular users
    if user['is_admin']:
        organizations = db.get_all_organizations()
    else:
        organizations = user['organizations']

    # Sort organizations: current organization first, then alphabetically by name
    current_org_id = session.get('current_organization_id')

    # Separate current organization and other organizations
    current_org = None
    other_orgs = []

    for org in organizations:
        if org['id'] == current_org_id:
            current_org = org
        else:
            other_orgs.append(org)

    # Sort other organizations alphabetically by name
    other_orgs = sorted(other_orgs, key=lambda x: x['name'].lower())

    # Combine current organization and other organizations
    sorted_organizations = []
    if current_org:
        sorted_organizations.append(current_org)
    sorted_organizations.extend(other_orgs)

    return render_template('organizations.html',
                          organizations=sorted_organizations,
                          user=user)

@app.route('/organizations/switch/<int:org_id>')
@auth.login_required
def switch_organization(org_id):
    """Switch current organization"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = False
    for org in user['organizations']:
        if org['id'] == org_id:
            has_access = True
            break

    # Admin users have access to all organizations
    if user['is_admin'] and not has_access:
        org = db.get_organization(org_id)
        if org:
            has_access = True

    if has_access:
        session['current_organization_id'] = org_id
        flash(f"Switched to organization: {org['name']}", 'success')
    else:
        flash("You don't have access to this organization", 'error')

    return redirect(request.referrer or url_for('index'))

@app.route('/organizations/create', methods=['GET', 'POST'])
@auth.admin_required
def create_organization():
    """Create a new organization"""
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')

        if not name:
            flash('Organization name is required', 'error')
            return redirect(url_for('create_organization'))

        # Check if organization already exists
        existing_org = db.get_organization_by_name(name)
        if existing_org:
            flash(f'Organization "{name}" already exists', 'error')
            return redirect(url_for('create_organization'))

        # Create organization
        org_id = db.create_organization(name, description)
        if org_id:
            flash(f'Organization "{name}" created successfully', 'success')
            return redirect(url_for('organizations'))
        else:
            flash('Failed to create organization', 'error')
            return redirect(url_for('create_organization'))

    return render_template('organization_form.html',
                          title='Create Organization',
                          user=auth.get_current_user())

@app.route('/organizations/<int:org_id>/edit', methods=['GET', 'POST'])
@auth.admin_required
def edit_organization(org_id):
    """Edit an organization"""
    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    if request.method == 'POST':
        form_type = request.form.get('form_type', 'organization_details')

        if form_type == 'organization_details':
            name = request.form.get('name')
            description = request.form.get('description')

            if not name:
                flash('Organization name is required', 'error')
                return redirect(url_for('edit_organization', org_id=org_id))

            # Check if new name already exists for another organization
            existing_org = db.get_organization_by_name(name)
            if existing_org and existing_org['id'] != org_id:
                flash(f'Organization "{name}" already exists', 'error')
                return redirect(url_for('edit_organization', org_id=org_id))

            # Update organization
            success = db.update_organization(org_id, name, description)
            if success:
                flash(f'Organization "{name}" updated successfully', 'success')
                return redirect(url_for('edit_organization', org_id=org_id))
            else:
                flash('Failed to update organization', 'error')
                return redirect(url_for('edit_organization', org_id=org_id))

    # Get organization users, tags, and domains for the editor
    users = db.get_organization_users(org_id)
    tags = db.get_organization_tags(org_id)
    domains = db.get_domains_by_organization(org_id)

    # Get SSL status for each domain
    for domain in domains:
        if domain['ssl_monitored']:
            cert_status = check_certificate(domain['name'])
            domain['ssl_status'] = cert_status.status
        else:
            domain['ssl_status'] = None

    return render_template('organization_editor.html',
                          organization=org,
                          users=users,
                          tags=tags,
                          domains=domains,
                          user=auth.get_current_user())

@app.route('/organizations/<int:org_id>/delete', methods=['POST'])
@auth.admin_required
def delete_organization(org_id):
    """Delete an organization"""
    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    # Delete organization
    success = db.delete_organization(org_id)
    if success:
        # If the deleted organization was the current one, reset the current organization
        if session.get('current_organization_id') == org_id:
            session.pop('current_organization_id', None)

        flash(f'Organization "{org["name"]}" deleted successfully', 'success')
    else:
        flash('Failed to delete organization', 'error')

    return redirect(url_for('organizations'))

@app.route('/organizations/<int:org_id>/users')
@auth.organization_admin_required
def organization_users(org_id):
    """Organization users page"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = user['is_admin']
    if not has_access:
        for org in user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to view this page", 'error')
        return redirect(url_for('index'))

    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    users = db.get_organization_users(org_id)

    return render_template('organization_users.html',
                          organization=org,
                          users=users,
                          user=user)

@app.route('/api/check_user_exists', methods=['GET'])
@auth.login_required
def api_check_user_exists():
    """API endpoint to check if a user exists"""
    username = request.args.get('username')
    if not username:
        return jsonify({'exists': False, 'message': 'Username is required'})

    # Get user by username
    user = db.get_user_by_username(username)
    if user:
        return jsonify({'exists': True, 'message': 'User found'})
    else:
        return jsonify({'exists': False, 'message': 'User not found'})

@app.route('/api/get_user_suggestions', methods=['GET'])
@auth.login_required
def api_get_user_suggestions():
    """API endpoint to get user suggestions"""
    query = request.args.get('query', '')
    org_id = request.args.get('org_id')

    logger.debug(f"User suggestion request - query: '{query}', org_id: {org_id}")

    if not org_id:
        logger.warning("User suggestion request missing org_id")
        return jsonify({'success': False, 'message': 'Organization ID is required'})

    try:
        # Get current user
        current_user = auth.get_current_user()
        logger.debug(f"Current user: {current_user['username']}, admin: {current_user['is_admin']}")

        # Check if user has access to this organization
        has_access = current_user['is_admin']
        if not has_access:
            for org in current_user['organizations']:
                if org['id'] == int(org_id) and org['role'] == 'admin':
                    has_access = True
                    break

        logger.debug(f"User has access to organization: {has_access}")

        if not has_access:
            logger.warning(f"Access denied for user {current_user['username']} to organization {org_id}")
            return jsonify({'success': False, 'message': 'Access denied'})

        # Get users that match the query and are not already in the organization
        users = db.get_users_by_partial_username(query)
        logger.debug(f"Found {len(users)} users matching query '{query}'")

        org_users = db.get_organization_users(int(org_id))
        logger.debug(f"Organization {org_id} has {len(org_users)} users")

        org_user_ids = [user['id'] for user in org_users]

        # Filter out users that are already in the organization
        filtered_users = [user for user in users if user['id'] not in org_user_ids]
        logger.debug(f"After filtering, {len(filtered_users)} users remain")

        # Format user data for suggestions
        suggestions = []
        for user in filtered_users:
            suggestions.append(user['username'])
            logger.debug(f"Adding suggestion: {user['username']}")

        response = {'success': True, 'suggestions': suggestions}
        logger.debug(f"Returning response: {response}")
        return jsonify(response)
    except Exception as e:
        logger.error(f"Error in get_user_suggestions: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

@app.route('/api/get_available_users', methods=['GET'])
@auth.login_required
def api_get_available_users():
    """API endpoint to get all available users for an organization"""
    org_id = request.args.get('org_id')
    search = request.args.get('search', '')

    logger.debug(f"Available users request - org_id: {org_id}, search: '{search}'")

    if not org_id:
        logger.warning("Available users request missing org_id")
        return jsonify({'success': False, 'message': 'Organization ID is required'})

    try:
        # Get current user
        current_user = auth.get_current_user()
        logger.debug(f"Current user: {current_user['username']} (ID: {current_user['id']})")

        # Check if user has access to this organization
        has_access = current_user['is_admin']
        if not has_access:
            for org in current_user['organizations']:
                if org['id'] == int(org_id) and org['role'] == 'admin':
                    has_access = True
                    break

        if not has_access:
            logger.warning(f"Access denied for user {current_user['username']} to organization {org_id}")
            return jsonify({'success': False, 'message': 'Access denied'})

        # Get all users
        all_users = db.get_all_users()
        logger.debug(f"Total users in system: {len(all_users)}")

        # Log all users for debugging
        for user in all_users:
            logger.debug(f"User in system: {user['username']} (ID: {user['id']})")

        # Get organization users
        org_users = db.get_organization_users(int(org_id))
        logger.debug(f"Users in organization {org_id}: {len(org_users)}")

        org_user_ids = [user['id'] for user in org_users]
        logger.debug(f"Organization user IDs: {org_user_ids}")

        # Filter out users that are already in the organization
        available_users = []
        for user in all_users:
            if user['id'] not in org_user_ids:
                available_users.append({
                    'id': user['id'],
                    'username': user['username'],
                    'email': user['email'],
                    'is_admin': user['is_admin']
                })
                logger.debug(f"Adding available user: {user['username']} (ID: {user['id']})")

        # Apply search filter if provided
        if search:
            search = search.lower()
            filtered_users = []
            for user in available_users:
                if search in user['username'].lower() or search in user['email'].lower():
                    filtered_users.append(user)
                    logger.debug(f"User matches search: {user['username']}")
            available_users = filtered_users

        logger.debug(f"Found {len(available_users)} available users for organization {org_id}")
        logger.debug(f"Available users: {[user['username'] for user in available_users]}")

        # If no users are available, create a test user for demonstration
        if len(available_users) == 0 and current_user['is_admin']:
            logger.debug("No available users found, creating a test user")
            test_username = f"testuser_{int(time.time())}"
            test_email = f"{test_username}@example.com"

            # Create the test user
            test_user_id = db.add_user(test_username, "password123", test_email, is_admin=False)
            if test_user_id:
                logger.debug(f"Created test user: {test_username} with ID {test_user_id}")
                available_users.append({
                    'id': test_user_id,
                    'username': test_username,
                    'email': test_email,
                    'is_admin': False
                })

        return jsonify({
            'success': True,
            'users': available_users
        })
    except Exception as e:
        logger.error(f"Error in get_available_users: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'})

@app.route('/api/debug_user_suggestions', methods=['POST'])
@auth.login_required
def api_debug_user_suggestions():
    """Debug endpoint for user suggestions"""
    try:
        data = request.json
        query = data.get('query', '')
        org_id = data.get('org_id')

        logger.debug(f"Debug user suggestions - query: '{query}', org_id: {org_id}")

        # Get current user
        current_user = auth.get_current_user()

        # Create a test user if we don't have many users
        all_users = db.get_all_users()

        if len(all_users) < 3:  # If we have fewer than 3 users
            test_username = f"testuser_{int(time.time())}"
            test_email = f"{test_username}@example.com"

            # Create the test user
            test_user_id = db.add_user(test_username, "password123", test_email, is_admin=False)
            logger.debug(f"Created test user: {test_username} with ID {test_user_id}")

            # Refresh the list of all users
            all_users = db.get_all_users()

        # Get users matching the query
        matching_users = db.get_users_by_partial_username(query)

        # Get organization users
        org_users = db.get_organization_users(int(org_id)) if org_id else []

        return jsonify({
            'success': True,
            'debug_info': {
                'query': query,
                'org_id': org_id,
                'current_user': current_user['username'],
                'total_users': len(all_users),
                'matching_users': [u['username'] for u in matching_users],
                'org_users': [u['username'] for u in org_users],
                'test_username': test_username
            }
        })
    except Exception as e:
        logger.error(f"Error in debug_user_suggestions: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'message': f'Debug error: {str(e)}'})

@app.route('/organizations/<int:org_id>/users/add', methods=['GET', 'POST'])
@auth.organization_admin_required
def add_organization_user(org_id):
    """Add users to an organization"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = user['is_admin']
    if not has_access:
        for org in user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to view this page", 'error')
        return redirect(url_for('index'))

    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    if request.method == 'POST':
        # Get selected users and role
        selected_users = request.form.getlist('selected_users[]')
        role = request.form.get('role', 'member')

        if not selected_users:
            flash('Please select at least one user to add', 'error')
            return redirect(url_for('add_organization_user', org_id=org_id))

        # Track success and failures
        added_users = []
        failed_users = []

        for user_id in selected_users:
            try:
                user_id = int(user_id)

                # Get user by ID
                user_to_add = db.get_user_by_id(user_id)
                if not user_to_add:
                    failed_users.append(f"User ID {user_id} not found")
                    continue

                # Check if user is already in organization
                if db.is_user_in_organization(user_id, org_id):
                    failed_users.append(f"User '{user_to_add['username']}' is already in this organization")
                    continue

                # Add user to organization
                success = db.add_user_to_organization(user_id, org_id, role)
                if success:
                    added_users.append(user_to_add['username'])
                else:
                    failed_users.append(f"Failed to add user '{user_to_add['username']}'")
            except Exception as e:
                logger.error(f"Error adding user {user_id} to organization: {str(e)}")
                failed_users.append(f"Error processing user ID {user_id}")

        # Show success and failure messages
        if added_users:
            if len(added_users) == 1:
                flash(f"User '{added_users[0]}' added to organization successfully", 'success')
            else:
                flash(f"{len(added_users)} users added to organization successfully", 'success')

        if failed_users:
            for message in failed_users:
                flash(message, 'error')

        if added_users:
            return redirect(url_for('organization_users', org_id=org_id))
        else:
            return redirect(url_for('add_organization_user', org_id=org_id))

    # Get current organization users for display
    org_users = db.get_organization_users(org_id)

    # Get all users in the system
    all_users = db.get_all_users()

    # Filter out users that are already in the organization
    org_user_ids = [user['id'] for user in org_users]
    available_users = [
        {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'is_admin': user['is_admin']
        }
        for user in all_users
        if user['id'] not in org_user_ids
    ]

    logger.debug(f"Found {len(available_users)} available users for organization {org_id}")

    # If no real users are available, add some test users for demonstration
    if len(available_users) == 0:
        available_users = [
            {
                'id': 1001,
                'username': 'testuser1',
                'email': 'testuser1@example.com',
                'is_admin': False
            },
            {
                'id': 1002,
                'username': 'testuser2',
                'email': 'testuser2@example.com',
                'is_admin': False
            },
            {
                'id': 1003,
                'username': 'adminuser',
                'email': 'admin@example.com',
                'is_admin': True
            }
        ]
        logger.debug("No real users available, using test users instead")

    # For GET requests, render the simplified template
    return render_template('add_members_simple.html',
                          organization=org,
                          users=org_users,
                          available_users=available_users,
                          user=user)

@app.route('/organizations/<int:org_id>/users/add/debug', methods=['GET'])
@auth.organization_admin_required
def debug_add_organization_user(org_id):
    """Debug page for adding users to an organization"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = user['is_admin']
    if not has_access:
        for org in user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to view this page", 'error')
        return redirect(url_for('index'))

    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    # Get current organization users for display
    users = db.get_organization_users(org_id)

    # Render the debug template
    return render_template('debug_info.html',
                          organization=org,
                          users=users,
                          user=user)

@app.route('/organizations/<int:org_id>/users/<int:user_id>/role', methods=['POST'])
@auth.organization_admin_required
def update_organization_user_role(org_id, user_id):
    """Update a user's role in an organization"""
    current_user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = current_user['is_admin']
    if not has_access:
        for org in current_user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to perform this action", 'error')
        return redirect(url_for('index'))

    # Don't allow changing own role
    if user_id == current_user['id']:
        flash("You cannot change your own role", 'error')
        return redirect(url_for('organization_users', org_id=org_id))

    role = request.form.get('role')
    if not role or role not in ['admin', 'member']:
        flash('Invalid role', 'error')
        return redirect(url_for('organization_users', org_id=org_id))

    # Update user role
    success = db.update_user_organization_role(user_id, org_id, role)
    if success:
        flash('User role updated successfully', 'success')
    else:
        flash('Failed to update user role', 'error')

    return redirect(url_for('organization_users', org_id=org_id))

@app.route('/organizations/<int:org_id>/users/<int:user_id>/remove', methods=['POST'])
@auth.organization_admin_required
def remove_organization_user(org_id, user_id):
    """Remove a user from an organization"""
    current_user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = current_user['is_admin']
    if not has_access:
        for org in current_user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to perform this action", 'error')
        return redirect(url_for('index'))

    # Don't allow removing self
    if user_id == current_user['id']:
        flash("You cannot remove yourself from the organization", 'error')
        return redirect(url_for('organization_users', org_id=org_id))

    # Remove user from organization
    success = db.remove_user_from_organization(user_id, org_id)
    if success:
        flash('User removed from organization successfully', 'success')
    else:
        flash('Failed to remove user from organization', 'error')

    return redirect(url_for('organization_users', org_id=org_id))

# Tag Routes
@app.route('/organizations/<int:org_id>/tags')
@auth.organization_access_required
def organization_tags(org_id):
    """Organization tags page"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = user['is_admin']
    if not has_access:
        for org in user['organizations']:
            if org['id'] == org_id:
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to view this page", 'error')
        return redirect(url_for('index'))

    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    tags = db.get_organization_tags(org_id)

    return render_template('organization_tags.html',
                          organization=org,
                          tags=tags,
                          user=user)

@app.route('/organizations/<int:org_id>/tags/create', methods=['GET', 'POST'])
@auth.organization_admin_required
def create_tag(org_id):
    """Create a new tag"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = user['is_admin']
    if not has_access:
        for org in user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to view this page", 'error')
        return redirect(url_for('index'))

    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    if request.method == 'POST':
        name = request.form.get('name')
        color = request.form.get('color', '#6c757d')

        if not name:
            flash('Tag name is required', 'error')
            return redirect(url_for('create_tag', org_id=org_id))

        # Create tag
        tag_id = db.create_tag(org_id, name, color)
        if tag_id:
            flash(f'Tag "{name}" created successfully', 'success')
            return redirect(url_for('organization_tags', org_id=org_id))
        else:
            flash('Failed to create tag', 'error')
            return redirect(url_for('create_tag', org_id=org_id))

    return render_template('tag_form.html',
                          title='Create Tag',
                          organization=org,
                          user=user)

@app.route('/organizations/<int:org_id>/tags/<int:tag_id>/edit', methods=['GET', 'POST'])
@auth.organization_admin_required
def edit_tag(org_id, tag_id):
    """Edit a tag"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = user['is_admin']
    if not has_access:
        for org in user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to view this page", 'error')
        return redirect(url_for('index'))

    org = db.get_organization(org_id)
    if not org:
        flash('Organization not found', 'error')
        return redirect(url_for('organizations'))

    tag = db.get_tag(tag_id)
    if not tag or tag['organization_id'] != org_id:
        flash('Tag not found', 'error')
        return redirect(url_for('organization_tags', org_id=org_id))

    if request.method == 'POST':
        name = request.form.get('name')
        color = request.form.get('color', '#6c757d')

        if not name:
            flash('Tag name is required', 'error')
            return redirect(url_for('edit_tag', org_id=org_id, tag_id=tag_id))

        # Update tag
        success = db.update_tag(tag_id, name, color)
        if success:
            flash(f'Tag "{name}" updated successfully', 'success')
            return redirect(url_for('organization_tags', org_id=org_id))
        else:
            flash('Failed to update tag', 'error')
            return redirect(url_for('edit_tag', org_id=org_id, tag_id=tag_id))

    return render_template('tag_form.html',
                          title='Edit Tag',
                          organization=org,
                          tag=tag,
                          user=user)

@app.route('/organizations/<int:org_id>/tags/<int:tag_id>/delete', methods=['POST'])
@auth.organization_admin_required
def delete_tag(org_id, tag_id):
    """Delete a tag"""
    user = auth.get_current_user()

    # Check if user has access to this organization
    has_access = user['is_admin']
    if not has_access:
        for org in user['organizations']:
            if org['id'] == org_id and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        flash("You don't have permission to perform this action", 'error')
        return redirect(url_for('index'))

    tag = db.get_tag(tag_id)
    if not tag or tag['organization_id'] != org_id:
        flash('Tag not found', 'error')
        return redirect(url_for('organization_tags', org_id=org_id))

    # Delete tag
    success = db.delete_tag(tag_id)
    if success:
        flash(f'Tag "{tag["name"]}" deleted successfully', 'success')
    else:
        flash('Failed to delete tag', 'error')

    return redirect(url_for('organization_tags', org_id=org_id))

# User Profile Routes
@app.route('/profile', methods=['GET', 'POST'])
@auth.login_required
def profile():
    """User profile page"""
    current_user = auth.get_current_user()

    if request.method == 'POST':
        email = request.form.get('email')
        display_name = request.form.get('display_name', '')

        # Validate input
        if not email:
            flash('Email is required', 'error')
            return render_template('profile.html', user=current_user)

        # Check if email already exists (if changed)
        if email != current_user['email']:
            existing_user = db.get_user_by_email(email)
            if existing_user and existing_user['id'] != current_user['id']:
                flash('Email already in use by another account', 'error')
                return render_template('profile.html', user=current_user)

        # Update user profile
        success = db.update_user(
            user_id=current_user['id'],
            email=email
        )

        # Update display name in user preferences
        if success:
            # Store display name in user preferences
            set_user_preference(current_user['id'], 'display_name', display_name)
            flash('Profile updated successfully', 'success')
        else:
            flash('Error updating profile', 'error')

        # Refresh user data
        current_user = auth.get_current_user()

    # Get user preferences
    current_user['display_name'] = get_user_preference(current_user['id'], 'display_name', '')
    current_user['theme_preference'] = get_user_preference(current_user['id'], 'theme_preference', 'system')
    current_user['email_alerts'] = get_user_preference(current_user['id'], 'email_alerts', True)

    return render_template('profile.html', user=current_user)

@app.route('/change_password', methods=['POST'])
@auth.login_required
def change_password():
    """Change user password"""
    current_user = auth.get_current_user()

    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')

    # Validate input
    if not current_password or not new_password or not confirm_password:
        flash('All fields are required', 'error')
        return redirect(url_for('profile'))

    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('profile'))

    # Verify current password
    password_parts = current_user['password_hash'].split(':')
    if len(password_parts) != 2:
        flash('Invalid account configuration. Please contact an administrator.', 'error')
        return redirect(url_for('profile'))

    stored_hash, salt = password_parts
    if not auth.verify_password(current_password, stored_hash, salt):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('profile'))

    # Hash new password
    password_hash, salt = auth.hash_password(new_password)
    combined_hash = f"{password_hash}:{salt}"

    # Update password
    success = db.update_user(
        user_id=current_user['id'],
        password_hash=combined_hash
    )

    if success:
        # Delete all other sessions for this user
        db.delete_user_sessions(current_user['id'])

        # Create a new session for the current user
        session_token = auth.create_user_session(current_user['id'])

        # Set session cookie
        response = make_response(redirect(url_for('profile')))
        response.set_cookie(
            auth.SESSION_COOKIE_NAME,
            session_token,
            max_age=auth.SESSION_EXPIRY,
            httponly=True,
            secure=request.is_secure,
            samesite='Lax'
        )

        flash('Password changed successfully. All other sessions have been logged out.', 'success')
        return response
    else:
        flash('Error changing password', 'error')
        return redirect(url_for('profile'))

@app.route('/update_preferences', methods=['POST'])
@auth.login_required
def update_preferences():
    """Update user preferences"""
    current_user = auth.get_current_user()

    theme_preference = request.form.get('theme_preference', 'system')
    email_alerts = 'email_alerts' in request.form

    # Update preferences
    set_user_preference(current_user['id'], 'theme_preference', theme_preference)
    set_user_preference(current_user['id'], 'email_alerts', email_alerts)

    flash('Preferences updated successfully', 'success')
    return redirect(url_for('profile'))

# Helper functions for user preferences
def get_user_preference(user_id, key, default=None):
    """Get a user preference"""
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT value FROM user_preferences WHERE user_id = ? AND key = ?",
            (user_id, key)
        )
        result = cursor.fetchone()
        if result:
            # Handle boolean values
            if result['value'] == 'True':
                return True
            elif result['value'] == 'False':
                return False
            return result['value']
        return default

def set_user_preference(user_id, key, value):
    """Set a user preference"""
    # Convert boolean to string
    if isinstance(value, bool):
        value = str(value)

    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            # Check if preference exists
            cursor.execute(
                "SELECT id FROM user_preferences WHERE user_id = ? AND key = ?",
                (user_id, key)
            )
            result = cursor.fetchone()

            if result:
                # Update existing preference
                cursor.execute(
                    "UPDATE user_preferences SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                    (value, result['id'])
                )
            else:
                # Insert new preference
                cursor.execute(
                    "INSERT INTO user_preferences (user_id, key, value) VALUES (?, ?, ?)",
                    (user_id, key, value)
                )

            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Error setting user preference: {e}")
            return False

# User Administration Routes
@app.route('/user_admin')
@auth.login_required
@auth.admin_required
def user_admin():
    """User administration page"""
    users = db.get_all_users()

    # Get organizations for each user
    for user in users:
        user['organizations'] = db.get_user_organizations(user['id'])

    # Sort users alphabetically by username by default
    sort_by = request.args.get('sort', 'username')
    sort_order = request.args.get('order', 'asc')

    # Define sorting functions for different fields
    sort_functions = {
        'username': lambda x: x['username'].lower(),
        'email': lambda x: x['email'].lower(),
        'is_admin': lambda x: (0 if x['is_admin'] else 1),  # Admins first
        'is_active': lambda x: (0 if x['is_active'] else 1),  # Active users first
        'created_at': lambda x: x['created_at'] if x['created_at'] else 0
    }

    # Apply sorting
    if sort_by in sort_functions:
        users = sorted(users, key=sort_functions[sort_by], reverse=(sort_order == 'desc'))

    organizations = db.get_all_organizations()
    return render_template('user_admin.html',
                          users=users,
                          organizations=organizations,
                          sort_by=sort_by,
                          sort_order=sort_order)

@app.route('/user_admin/add', methods=['POST'])
@auth.login_required
@auth.admin_required
def user_admin_add():
    """Add a new user"""
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    is_admin = request.form.get('is_admin') == '1'

    # Validate input
    if not username or not email or not password or not confirm_password:
        flash('Please fill in all fields', 'error')
        return redirect(url_for('user_admin'))

    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('user_admin'))

    # Check if username or email already exists
    if db.get_user_by_username(username):
        flash('Username already exists', 'error')
        return redirect(url_for('user_admin'))

    if db.get_user_by_email(email):
        flash('Email already exists', 'error')
        return redirect(url_for('user_admin'))

    # Hash password
    password_hash, salt = auth.hash_password(password)
    combined_hash = f"{password_hash}:{salt}"

    # Create user
    user_id = db.create_user(username, email, combined_hash, is_admin=is_admin)
    if not user_id:
        flash('Error creating user', 'error')
        return redirect(url_for('user_admin'))

    flash(f'User {username} created successfully', 'success')
    return redirect(url_for('user_admin'))

@app.route('/user_admin/edit', methods=['POST'])
@auth.login_required
@auth.admin_required
def user_admin_edit():
    """Edit a user"""
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')
    is_admin = request.form.get('is_admin') == '1'
    is_active = request.form.get('is_active') == '1'

    # Validate input
    if not user_id or not username or not email:
        flash('Please fill in all fields', 'error')
        return redirect(url_for('user_admin'))

    # Get the user
    user = db.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('user_admin'))

    # Check if username or email already exists (if changed)
    if username != user['username'] and db.get_user_by_username(username):
        flash('Username already exists', 'error')
        return redirect(url_for('user_admin'))

    if email != user['email'] and db.get_user_by_email(email):
        flash('Email already exists', 'error')
        return redirect(url_for('user_admin'))

    # Update user
    success = db.update_user(
        user_id=user_id,
        username=username,
        email=email,
        is_admin=is_admin,
        is_active=is_active
    )

    if not success:
        flash('Error updating user', 'error')
        return redirect(url_for('user_admin'))

    flash(f'User {username} updated successfully', 'success')
    return redirect(url_for('user_admin'))

@app.route('/user_admin/reset_password', methods=['POST'])
@auth.login_required
@auth.admin_required
def user_admin_reset_password():
    """Reset a user's password"""
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    # Validate input
    if not user_id or not new_password or not confirm_new_password:
        flash('Please fill in all fields', 'error')
        return redirect(url_for('user_admin'))

    if new_password != confirm_new_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('user_admin'))

    # Get the user
    user = db.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('user_admin'))

    # Hash password
    password_hash, salt = auth.hash_password(new_password)
    combined_hash = f"{password_hash}:{salt}"

    # Update user
    success = db.update_user(
        user_id=user_id,
        password_hash=combined_hash
    )

    if not success:
        flash('Error resetting password', 'error')
        return redirect(url_for('user_admin'))

    # Invalidate all sessions for this user
    db.delete_user_sessions(user_id)

    flash(f'Password for {user["username"]} reset successfully', 'success')
    return redirect(url_for('user_admin'))

@app.route('/user_admin/delete', methods=['POST'])
@auth.login_required
@auth.admin_required
def user_admin_delete():
    """Delete a user"""
    user_id = request.form.get('user_id')

    # Validate input
    if not user_id:
        flash('Invalid request', 'error')
        return redirect(url_for('user_admin'))

    # Get the user
    user = db.get_user_by_id(user_id)
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('user_admin'))

    # Check if user is trying to delete themselves
    current_user = auth.get_current_user()
    if str(current_user['id']) == str(user_id):
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('user_admin'))

    # Delete user
    success = db.delete_user(user_id)
    if not success:
        flash('Error deleting user', 'error')
        return redirect(url_for('user_admin'))

    flash(f'User {user["username"]} deleted successfully', 'success')
    return redirect(url_for('user_admin'))

# API Routes for User Organization Management
@app.route('/api/users/<int:user_id>/organizations')
@auth.login_required
def api_get_user_organizations(user_id):
    """API endpoint to get a user's organizations"""

    # Check if user has permission to view this user's organizations
    current_user = auth.get_current_user()

    # System admins can view any user's organizations
    has_access = current_user['is_admin']

    # Users can view their own organizations
    if not has_access and current_user['id'] == user_id:
        has_access = True

    if not has_access:
        return jsonify({'success': False, 'message': 'You do not have permission to view this user\'s organizations'}), 403
    # Get the user
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Get user's organizations
    organizations = db.get_user_organizations(user_id)

    return jsonify({
        'success': True,
        'organizations': organizations
    })

@app.route('/api/users/add_to_organization', methods=['POST'])
@auth.login_required
def api_add_user_to_organization():
    """API endpoint to add a user to an organization"""
    data = request.json
    user_id = data.get('user_id')
    org_id = data.get('org_id')
    role = data.get('role', 'member')

    # Check if user has permission to add users to this organization
    current_user = auth.get_current_user()
    has_access = current_user['is_admin']

    if not has_access and org_id:
        # Check if user is an admin of this organization
        for org in current_user['organizations']:
            if org['id'] == int(org_id) and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        return jsonify({'success': False, 'message': 'You do not have permission to add users to this organization'}), 403

    # Validate input
    if not user_id or not org_id:
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400

    # Check if user exists
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Check if organization exists
    org = db.get_organization(org_id)
    if not org:
        return jsonify({'success': False, 'message': 'Organization not found'}), 404

    # Check if user is already in organization
    if db.is_user_in_organization(user_id, org_id):
        return jsonify({'success': False, 'message': 'User is already a member of this organization'}), 400

    # Add user to organization
    result = db.add_user_to_organization(user_id, org_id, role)
    if not result:
        return jsonify({'success': False, 'message': 'Error adding user to organization'}), 500

    return jsonify({
        'success': True,
        'message': f'User added to {org["name"]} as {role}'
    })

@app.route('/api/users/update_organization_role', methods=['POST'])
@auth.login_required
def api_update_user_organization_role():
    """API endpoint to update a user's role in an organization"""

    # Check if user has permission to update roles in this organization
    data = request.json
    org_id = data.get('org_id')

    current_user = auth.get_current_user()
    has_access = current_user['is_admin']

    if not has_access and org_id:
        # Check if user is an admin of this organization
        for org in current_user['organizations']:
            if org['id'] == int(org_id) and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        return jsonify({'success': False, 'message': 'You do not have permission to update roles in this organization'}), 403

    user_id = data.get('user_id')
    # org_id is already retrieved above
    role = data.get('role')

    # Validate input
    if not user_id or not org_id or not role:
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400

    # Check if user exists
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Check if organization exists
    org = db.get_organization(org_id)
    if not org:
        return jsonify({'success': False, 'message': 'Organization not found'}), 404

    # Check if user is in organization
    if not db.is_user_in_organization(user_id, org_id):
        return jsonify({'success': False, 'message': 'User is not a member of this organization'}), 400

    # Update user's role
    success = db.update_user_organization_role(user_id, org_id, role)
    if not success:
        return jsonify({'success': False, 'message': 'Error updating user role'}), 500

    return jsonify({
        'success': True,
        'message': f'User role updated to {role} in {org["name"]}'
    })

@app.route('/api/users/remove_from_organization', methods=['POST'])
@auth.login_required
def api_remove_user_from_organization():
    """API endpoint to remove a user from an organization"""

    # Check if user has permission to remove users from this organization
    data = request.json
    org_id = data.get('org_id')

    current_user = auth.get_current_user()
    has_access = current_user['is_admin']

    if not has_access and org_id:
        # Check if user is an admin of this organization
        for org in current_user['organizations']:
            if org['id'] == int(org_id) and org['role'] == 'admin':
                has_access = True
                break

    if not has_access:
        return jsonify({'success': False, 'message': 'You do not have permission to remove users from this organization'}), 403

    user_id = data.get('user_id')
    # org_id is already retrieved above

    # Validate input
    if not user_id or not org_id:
        return jsonify({'success': False, 'message': 'Missing required parameters'}), 400

    # Check if user exists
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    # Check if organization exists
    org = db.get_organization(org_id)
    if not org:
        return jsonify({'success': False, 'message': 'Organization not found'}), 404

    # Check if user is in organization
    if not db.is_user_in_organization(user_id, org_id):
        return jsonify({'success': False, 'message': 'User is not a member of this organization'}), 400

    # Remove user from organization
    success = db.remove_user_from_organization(user_id, org_id)
    if not success:
        return jsonify({'success': False, 'message': 'Error removing user from organization'}), 500

    return jsonify({
        'success': True,
        'message': f'User removed from {org["name"]}'
    })

@app.route('/api/organizations/<int:org_id>/domains', methods=['GET'])
@auth.login_required
def api_get_organization_domains(org_id):
    """API endpoint to get domains for an organization"""
    try:
        # Get current user
        current_user = auth.get_current_user()

        # Check if user has access to this organization
        has_access = current_user['is_admin']
        if not has_access:
            for org in current_user['organizations']:
                if org['id'] == org_id:
                    has_access = True
                    break

        if not has_access:
            return jsonify({'success': False, 'message': 'You do not have permission to view domains for this organization'}), 403

        # Get domains for the organization
        domains = db.get_domains_by_organization(org_id)

        # Format the response
        formatted_domains = []
        for domain in domains:
            formatted_domains.append({
                'id': domain['id'],
                'name': domain['name'],
                'ssl_monitored': domain['ssl_monitored'],
                'expiry_monitored': domain['expiry_monitored'],
                'ping_monitored': domain['ping_monitored']
            })

        return jsonify({
            'success': True,
            'domains': formatted_domains
        })
    except Exception as e:
        logger.error(f"Error getting domains for organization {org_id}: {str(e)}")
        return jsonify({'success': False, 'message': f'Server error: {str(e)}'}), 500

# Background task for periodic ping checks
def run_periodic_ping_checks():
    """Run ping checks for all domains with ping monitoring enabled every 60 seconds"""
    logger.info("Starting periodic ping checks thread")

    while True:
        try:
            # Get all domains with ping monitoring enabled
            all_domains = db.get_all_domains()
            ping_domains = [domain for domain in all_domains if domain.get('ping_monitored', False)]

            if ping_domains:
                logger.info(f"Running periodic ping checks for {len(ping_domains)} domains")

                for domain in ping_domains:
                    try:
                        domain_name = domain.get('name')
                        if domain_name:
                            # Check ping status and record it in the database
                            # This will automatically update the ping history
                            ping_result = check_ping(domain_name)
                            logger.debug(f"Periodic ping check for {domain_name}: {ping_result['status']} ({ping_result['response_time']} ms)")
                    except Exception as e:
                        logger.error(f"Error in periodic ping check for domain {domain.get('name', 'unknown')}: {str(e)}")

                logger.info("Completed periodic ping checks")
            else:
                logger.debug("No domains with ping monitoring enabled found")

        except Exception as e:
            logger.error(f"Error in periodic ping checks: {str(e)}", exc_info=True)

        # Sleep for 60 seconds before the next check
        time.sleep(60)

# Function to add test ping data for a domain
def add_test_ping_data(domain_name, num_entries=24):
    """Add test ping data for a domain to populate the response time chart"""
    logger.info(f"Adding {num_entries} test ping entries for {domain_name}")

    # Get the domain
    domain = db.get_domain_by_name(domain_name)
    if not domain:
        logger.error(f"Domain {domain_name} not found!")
        return False

    # Generate test data
    current_time = datetime.now()
    success_count = 0

    for i in range(num_entries):
        # Create a timestamp going back in time
        timestamp = current_time - timedelta(hours=i)

        # Generate a random response time between 10ms and 200ms
        import random
        response_time = random.randint(10, 200)

        # Most entries should be 'up', but add some 'down' entries randomly
        status = 'up' if random.random() > 0.1 else 'down'

        # Record the ping status
        success = db.record_ping_status(domain_name, status, response_time)
        if success:
            success_count += 1

    logger.info(f"Successfully added {success_count} ping entries for {domain_name}")
    return True

# Start the background task in a separate thread
def start_background_tasks():
    """Start all background tasks in separate threads"""
    ping_thread = threading.Thread(target=run_periodic_ping_checks, daemon=True)
    ping_thread.start()
    logger.info("Background tasks started")

if __name__ == '__main__':
    # Initialize database
    db.init_db()

    # Initialize authentication system (create default admin user if needed)
    try:
        auth.initialize_auth()
        logger.info("Authentication system initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing authentication system: {str(e)}", exc_info=True)

    # Start background tasks
    start_background_tasks()

    # Start the application
    if os.getenv('FLASK_ENV') == 'production':
        # Production settings
        try:
            from waitress import serve
            serve(app, host='0.0.0.0', port=5000)
        except ImportError:
            app.run(debug=False, host='0.0.0.0', port=5000)
    else:
        # Development settings
        app.run(debug=True, host='0.0.0.0', port=5000)
