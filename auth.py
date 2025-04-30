import os
import hashlib
import secrets
import time
from functools import wraps
from flask import request, redirect, url_for, session, flash, g
import database as db

# Constants
SESSION_COOKIE_NAME = 'certifly_session'
SESSION_EXPIRY = 86400 * 7  # 7 days in seconds
PASSWORD_SALT_LENGTH = 16
DEFAULT_ADMIN_USERNAME = 'admin'
DEFAULT_ADMIN_EMAIL = 'admin@example.com'
DEFAULT_ADMIN_PASSWORD = 'admin'  # This should be changed after first login

def hash_password(password, salt=None):
    """
    Hash a password with a salt using PBKDF2 with SHA-256

    Args:
        password (str): The password to hash
        salt (str, optional): The salt to use. If None, a new salt will be generated.

    Returns:
        tuple: (hash, salt)
    """
    if salt is None:
        salt = secrets.token_hex(PASSWORD_SALT_LENGTH)

    # Use PBKDF2 with SHA-256, 100,000 iterations
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()

    return key, salt

def verify_password(password, stored_hash, salt):
    """
    Verify a password against a stored hash and salt

    Args:
        password (str): The password to verify
        stored_hash (str): The stored hash
        salt (str): The salt used to create the hash

    Returns:
        bool: True if the password matches, False otherwise
    """
    calculated_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(calculated_hash, stored_hash)

def generate_session_token():
    """Generate a secure random session token"""
    return secrets.token_hex(32)

def create_user_session(user_id):
    """
    Create a new session for a user

    Args:
        user_id (int): The user ID

    Returns:
        str: The session token
    """
    # Generate a session token
    session_token = generate_session_token()

    # Calculate expiry time
    expires_at = time.time() + SESSION_EXPIRY

    # Create session in database
    db.create_session(user_id, session_token, expires_at)

    # Update last login time
    db.update_last_login(user_id)

    return session_token

def get_current_user():
    """
    Get the current user from the session

    Returns:
        dict: The user object or None if not logged in
    """
    # Check if user is already in g
    if hasattr(g, 'user'):
        return g.user

    # Check if session token is in cookies
    session_token = request.cookies.get(SESSION_COOKIE_NAME)
    if not session_token:
        return None

    # Get session from database
    session_data = db.get_session(session_token)
    if not session_data:
        return None

    # Get user from database
    user = db.get_user_by_id(session_data['user_id'])
    if not user:
        return None

    # Check if user is active
    if not user['is_active']:
        return None

    # Get user's organizations
    user_orgs = db.get_user_organizations(user['id'])

    # Add organizations to user object
    user['organizations'] = user_orgs

    # Get current organization from session or use first organization
    current_org_id = session.get('current_organization_id')
    if current_org_id:
        # Verify user has access to this organization
        for org in user_orgs:
            if org['id'] == current_org_id:
                user['current_organization'] = org
                break

        # If user doesn't have access to the organization in session, try to get it directly
        if 'current_organization' not in user:
            org = db.get_organization(current_org_id)
            if org and (user['is_admin'] or db.is_user_in_organization(user['id'], current_org_id)):
                # Add role information
                org['role'] = db.get_user_organization_role(user['id'], current_org_id) or 'member'
                user['current_organization'] = org

    # If no current organization set or user doesn't have access, use first organization
    if 'current_organization' not in user and user_orgs:
        user['current_organization'] = user_orgs[0]
        session['current_organization_id'] = user_orgs[0]['id']

    # Store user in g for this request
    g.user = user
    return user

def login_required(f):
    """
    Decorator to require login for a route

    Usage:
        @app.route('/protected')
        @login_required
        def protected():
            return 'This is a protected page'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """
    Decorator to require admin privileges for a route

    Usage:
        @app.route('/admin')
        @admin_required
        def admin():
            return 'This is an admin page'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return redirect(url_for('login', next=request.url))
        if not user['is_admin']:
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def create_default_admin():
    """
    Create a default admin user if no users exist

    Returns:
        bool: True if admin was created, False otherwise
    """
    # Check if any users exist
    with db.get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM users")
        result = cursor.fetchone()

        if result and result['count'] > 0:
            return False

    # Hash the default password
    password_hash, salt = hash_password(DEFAULT_ADMIN_PASSWORD)

    # Store the password hash and salt
    combined_hash = f"{password_hash}:{salt}"

    # Create the admin user
    user_id = db.create_user(
        username=DEFAULT_ADMIN_USERNAME,
        email=DEFAULT_ADMIN_EMAIL,
        password_hash=combined_hash,
        is_admin=True
    )

    if user_id:
        # Add admin to default organization with admin role
        db.add_user_to_organization(user_id, 1, 'admin')
        return True

    return False

def organization_admin_required(f):
    """
    Decorator to require organization admin privileges for a route

    Usage:
        @app.route('/org/admin')
        @organization_admin_required
        def org_admin():
            return 'This is an organization admin page'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return redirect(url_for('login', next=request.url))

        # Admin users have access to all organizations
        if user['is_admin']:
            return f(*args, **kwargs)

        # Check if user is an organization admin
        current_org = user.get('current_organization')
        if not current_org or current_org.get('role') != 'admin':
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function

def organization_access_required(f):
    """
    Decorator to require organization access for a route

    Usage:
        @app.route('/org/view')
        @organization_access_required
        def org_view():
            return 'This is an organization page'
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if user is None:
            return redirect(url_for('login', next=request.url))

        # Check if user has a current organization
        if not user.get('current_organization'):
            flash('You do not have access to any organizations', 'error')
            return redirect(url_for('index'))

        return f(*args, **kwargs)
    return decorated_function

def initialize_auth():
    """Initialize authentication system"""
    # Create default admin if no users exist
    if create_default_admin():
        print(f"Created default admin user: {DEFAULT_ADMIN_USERNAME} / {DEFAULT_ADMIN_PASSWORD}")
        print("Please change the password after first login!")

    # Clear expired sessions
    db.clear_expired_sessions()
