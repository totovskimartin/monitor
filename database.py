import os
import json
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Boolean, Text, JSON, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from contextlib import contextmanager

# Database configuration
DB_USER = os.getenv('DB_USER', 'certifly')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'certifly')

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

@contextmanager
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# For compatibility with code that expects a connection object
@contextmanager
def get_db_connection():
    """Get a database connection (compatibility function)"""
    with get_db() as db:
        yield db

# Models
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    profile_image = Column(String, nullable=True)  # Path to profile image
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    organizations = relationship("UserOrganization", back_populates="user", cascade="all, delete-orphan")
    alert_history = relationship("AlertHistory", back_populates="user", cascade="all, delete-orphan")
    action_logs = relationship("UserActionLog", foreign_keys="UserActionLog.user_id", cascade="all, delete-orphan")
    preferences = relationship("UserPreference", back_populates="user", cascade="all, delete-orphan")

class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    domains = relationship("Domain", back_populates="organization", cascade="all, delete-orphan")
    users = relationship("UserOrganization", back_populates="organization", cascade="all, delete-orphan")

class UserOrganization(Base):
    __tablename__ = "user_organizations"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    role = Column(String, default="member")  # admin, member
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="organizations")
    organization = relationship("Organization", back_populates="users")

class Domain(Base):
    __tablename__ = "domains"

    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = relationship("Organization", back_populates="domains")
    ssl_checks = relationship("SSLCheck", back_populates="domain", cascade="all, delete-orphan")
    domain_expiry_checks = relationship("DomainExpiryCheck", back_populates="domain", cascade="all, delete-orphan")
    ping_checks = relationship("PingCheck", back_populates="domain", cascade="all, delete-orphan")

class SSLCheck(Base):
    __tablename__ = "ssl_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"))
    status = Column(String)  # valid, warning, expired, error
    expiry_date = Column(DateTime)
    issuer = Column(String)
    subject = Column(String)
    checked_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="ssl_checks")

class DomainExpiryCheck(Base):
    __tablename__ = "domain_expiry_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"))
    status = Column(String)  # valid, warning, expired, error
    expiry_date = Column(DateTime)
    registrar = Column(String)
    checked_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="domain_expiry_checks")

class PingCheck(Base):
    __tablename__ = "ping_checks"

    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, ForeignKey("domains.id"))
    status = Column(String)  # up, down, unknown
    response_time = Column(Integer)  # in milliseconds
    checked_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    domain = relationship("Domain", back_populates="ping_checks")

class AlertHistory(Base):
    __tablename__ = "alert_history"

    id = Column(Integer, primary_key=True)
    alert_id = Column(String)
    domain_name = Column(String)
    alert_type = Column(String)  # ssl, domain, ping
    status = Column(String)  # warning, error, etc.
    message = Column(Text)
    action = Column(String)  # acknowledged, unacknowledged, deleted, restored
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="alert_history")

class UserActionLog(Base):
    __tablename__ = "user_action_logs"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String)
    action_type = Column(String)  # login, logout, create, update, delete, etc.
    resource_type = Column(String)  # domain, organization, user, alert, etc.
    resource_id = Column(String, nullable=True)  # ID of the affected resource
    resource_name = Column(String, nullable=True)  # Name of the affected resource
    details = Column(Text, nullable=True)  # Additional details about the action
    ip_address = Column(String, nullable=True)  # IP address of the user
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)  # Always stored in UTC

    # Relationships
    user = relationship("User", overlaps="action_logs")
    organization = relationship("Organization")

class Setting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True)
    value = Column(Text)  # JSON serialized
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class OrganizationSetting(Base):
    __tablename__ = "organization_settings"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    key = Column(String, nullable=False)
    value = Column(Text)  # JSON serialized
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Create a unique constraint on organization_id and key
    __table_args__ = (
        UniqueConstraint('organization_id', 'key', name='uix_org_setting'),
    )

    # Relationships
    organization = relationship("Organization")

class Cache(Base):
    __tablename__ = "cache"

    id = Column(Integer, primary_key=True)
    key = Column(String, unique=True)
    value = Column(Text)  # JSON serialized
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String, unique=True)
    expires_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="sessions")

class UserPreference(Base):
    __tablename__ = "user_preferences"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    key = Column(String, nullable=False)
    value = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Create a unique constraint on user_id and key
    __table_args__ = (
        UniqueConstraint('user_id', 'key', name='uix_user_preference'),
    )

    # Relationships
    user = relationship("User", back_populates="preferences")

# Session management functions
def create_session(user_id, session_token, expires_at):
    """Create a new session in the database"""
    with get_db() as db:
        session = Session(
            user_id=user_id,
            token=session_token,
            expires_at=datetime.fromtimestamp(expires_at)
        )
        db.add(session)
        db.commit()
        return session

def get_session(session_token):
    """Get session data from database"""
    with get_db() as db:
        session = db.query(Session).filter(
            Session.token == session_token,
            Session.expires_at > datetime.utcnow()
        ).first()

        if session:
            return {
                'user_id': session.user_id,
                'expires_at': session.expires_at.timestamp()
            }
        return None

def delete_session(session_token):
    """Delete a session from the database"""
    with get_db() as db:
        db.query(Session).filter(Session.token == session_token).delete()
        db.commit()

def cleanup_expired_sessions():
    """Delete all expired sessions"""
    with get_db() as db:
        db.query(Session).filter(Session.expires_at <= datetime.utcnow()).delete()
        db.commit()

# User management functions
def create_user(username, email, password_hash, is_admin=False):
    """Create a new user in the database"""
    with get_db() as db:
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            is_admin=is_admin
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user.id

def get_user_by_id(user_id):
    """Get user by ID"""
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            return {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'profile_image': user.profile_image,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'created_at': user.created_at.timestamp() if user.created_at else None
            }
        return None

def get_user_by_username(username):
    """Get user by username"""
    with get_db() as db:
        user = db.query(User).filter(User.username == username).first()
        if user:
            return {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'password_hash': user.password_hash,
                'profile_image': user.profile_image,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'created_at': user.created_at.timestamp() if user.created_at else None
            }
        return None

def get_user_by_email(email):
    """Get user by email"""
    with get_db() as db:
        user = db.query(User).filter(User.email == email).first()
        if user:
            return {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'password_hash': user.password_hash,
                'profile_image': user.profile_image,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'created_at': user.created_at.timestamp() if user.created_at else None
            }
        return None

def get_all_users():
    """Get all users"""
    with get_db() as db:
        users = db.query(User).all()
        return [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'profile_image': user.profile_image,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'created_at': user.created_at.timestamp() if user.created_at else None
            }
            for user in users
        ]

def get_users_by_partial_username(partial_username):
    """Get users by partial username match"""
    with get_db() as db:
        users = db.query(User).filter(User.username.ilike(f"%{partial_username}%")).all()
        return [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'profile_image': user.profile_image,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'created_at': user.created_at.timestamp() if user.created_at else None
            }
            for user in users
        ]

def update_user(user_id, username, email, is_admin=False, is_active=True):
    """Update user details"""
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        user.username = username
        user.email = email
        user.is_admin = is_admin
        user.is_active = is_active

        db.commit()
        return True

def update_user_email(user_id, email):
    """Update just the user's email"""
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        user.email = email
        db.commit()
        return True

def update_user_password(user_id, password_hash):
    """Update just the user's password"""
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        user.password_hash = password_hash
        db.commit()
        return True

def update_user_profile_image(user_id, image_path):
    """Update user's profile image path"""
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        user.profile_image = image_path
        db.commit()
        return True

def get_user_profile_image(user_id):
    """Get user's profile image path"""
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return None

        return user.profile_image

def delete_user(user_id):
    """Delete a user"""
    with get_db() as db:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            return False

        db.delete(user)
        db.commit()
        return True

def add_user(username, password, email, is_admin=False):
    """Add a new user (compatibility function)"""
    return create_user(username, email, password, is_admin)

def update_last_login(user_id):
    """Update the last login time for a user"""
    # This function is called by auth.py but doesn't need to do anything in our implementation
    # We could add a last_login field to the User model if needed
    return True

def delete_user_sessions(user_id):
    """Delete all sessions for a user"""
    with get_db() as db:
        db.query(Session).filter(Session.user_id == user_id).delete()
        db.commit()
        return True

def is_user_in_organization(user_id, org_id):
    """Check if a user is in an organization"""
    with get_db() as db:
        user_org = db.query(UserOrganization).filter(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id
        ).first()
        return user_org is not None

def get_user_organization_role(user_id, org_id):
    """Get a user's role in an organization"""
    with get_db() as db:
        user_org = db.query(UserOrganization).filter(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id
        ).first()
        return user_org.role if user_org else None

# Organization management functions
def create_organization(name, description=""):
    """Create a new organization"""
    with get_db() as db:
        org = Organization(
            name=name,
            description=description
        )
        db.add(org)
        db.commit()
        db.refresh(org)
        return org.id

def get_organization(org_id):
    """Get organization by ID"""
    with get_db() as db:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if org:
            return {
                'id': org.id,
                'name': org.name,
                'description': org.description,
                'created_at': org.created_at.timestamp() if org.created_at else None
            }
        return None

def get_organization_by_name(name):
    """Get organization by name"""
    with get_db() as db:
        org = db.query(Organization).filter(Organization.name == name).first()
        if org:
            return {
                'id': org.id,
                'name': org.name,
                'description': org.description,
                'created_at': org.created_at.timestamp() if org.created_at else None
            }
        return None

def get_all_organizations():
    """Get all organizations"""
    with get_db() as db:
        orgs = db.query(Organization).all()
        return [
            {
                'id': org.id,
                'name': org.name,
                'description': org.description,
                'created_at': org.created_at.timestamp() if org.created_at else None
            }
            for org in orgs
        ]

def update_organization(org_id, name, description):
    """Update organization details"""
    with get_db() as db:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            return False

        org.name = name
        org.description = description

        db.commit()
        return True

def delete_organization(org_id):
    """Delete an organization"""
    with get_db() as db:
        org = db.query(Organization).filter(Organization.id == org_id).first()
        if not org:
            return False

        db.delete(org)
        db.commit()
        return True

# User-Organization management functions
def add_user_to_organization(user_id, org_id, role="member"):
    """Add a user to an organization"""
    with get_db() as db:
        # Check if user is already in organization
        existing = db.query(UserOrganization).filter(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id
        ).first()

        if existing:
            # Update role if different
            if existing.role != role:
                existing.role = role
                db.commit()
            return True

        # Add user to organization
        user_org = UserOrganization(
            user_id=user_id,
            organization_id=org_id,
            role=role
        )
        db.add(user_org)
        db.commit()
        return True

def remove_user_from_organization(user_id, org_id):
    """Remove a user from an organization"""
    with get_db() as db:
        user_org = db.query(UserOrganization).filter(
            UserOrganization.user_id == user_id,
            UserOrganization.organization_id == org_id
        ).first()

        if not user_org:
            return False

        db.delete(user_org)
        db.commit()
        return True

def get_user_organizations(user_id):
    """Get all organizations a user belongs to"""
    with get_db() as db:
        user_orgs = db.query(UserOrganization).filter(
            UserOrganization.user_id == user_id
        ).all()

        org_ids = [user_org.organization_id for user_org in user_orgs]
        orgs = db.query(Organization).filter(Organization.id.in_(org_ids)).all()

        return [
            {
                'id': org.id,
                'name': org.name,
                'description': org.description,
                'role': next((user_org.role for user_org in user_orgs if user_org.organization_id == org.id), None),
                'created_at': org.created_at.timestamp() if org.created_at else None
            }
            for org in orgs
        ]

def get_organization_users(org_id):
    """Get all users in an organization"""
    with get_db() as db:
        user_orgs = db.query(UserOrganization).filter(
            UserOrganization.organization_id == org_id
        ).all()

        user_ids = [user_org.user_id for user_org in user_orgs]
        users = db.query(User).filter(User.id.in_(user_ids)).all()

        return [
            {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_admin': user.is_admin,
                'is_active': user.is_active,
                'role': next((user_org.role for user_org in user_orgs if user_org.user_id == user.id), None),
                'created_at': user.created_at.timestamp() if user.created_at else None
            }
            for user in users
        ]

def get_organization_tags(org_id):
    """Get all tags for an organization"""
    # This is a placeholder function since we don't have a Tag model yet
    # In a real implementation, we would query the database for tags
    # For now, return an empty list
    return []

# Domain management functions
def add_domain(name, organization_id, ssl_monitored=False, expiry_monitored=False, ping_monitored=False,
              user_id=None, username=None, ip_address=None, auto_log=False):
    """
    Add a new domain with monitoring options

    Args:
        name (str): Domain name
        organization_id (int): Organization ID
        ssl_monitored (bool): Whether SSL monitoring is enabled
        expiry_monitored (bool): Whether expiry monitoring is enabled
        ping_monitored (bool): Whether ping monitoring is enabled
        user_id (int, optional): User ID for logging
        username (str, optional): Username for logging
        ip_address (str, optional): IP address for logging
        auto_log (bool): Whether to automatically create a log entry

    Returns:
        int: Domain ID
    """
    import logging
    logger = logging.getLogger('certifly')

    with get_db() as db:
        # Check if domain already exists
        existing = db.query(Domain).filter(
            Domain.name == name,
            Domain.organization_id == organization_id
        ).first()

        if existing:
            # Domain already exists, update its monitoring settings
            domain_id = existing.id
            # Store monitoring options in organization settings
            set_organization_setting(organization_id, f"domain_{domain_id}_ssl_monitored", ssl_monitored)
            set_organization_setting(organization_id, f"domain_{domain_id}_expiry_monitored", expiry_monitored)
            set_organization_setting(organization_id, f"domain_{domain_id}_ping_monitored", ping_monitored)

            # Log the update if auto_log is enabled
            if auto_log and user_id and username:
                monitoring_types = []
                if ssl_monitored:
                    monitoring_types.append("SSL")
                if expiry_monitored:
                    monitoring_types.append("expiry")
                if ping_monitored:
                    monitoring_types.append("ping")

                monitoring_str = ", ".join(monitoring_types) if monitoring_types else "no"

                log_user_action(
                    user_id=user_id,
                    username=username,
                    action_type='update',
                    resource_type='domain',
                    resource_id=domain_id,
                    resource_name=name,
                    details=f'Updated domain with {monitoring_str} monitoring',
                    ip_address=ip_address,
                    organization_id=organization_id
                )

            return domain_id

        # Create new domain
        domain = Domain(
            name=name,
            organization_id=organization_id
        )
        db.add(domain)
        db.commit()
        db.refresh(domain)

        # Store monitoring options in organization settings
        domain_id = domain.id
        set_organization_setting(organization_id, f"domain_{domain_id}_ssl_monitored", ssl_monitored)
        set_organization_setting(organization_id, f"domain_{domain_id}_expiry_monitored", expiry_monitored)
        set_organization_setting(organization_id, f"domain_{domain_id}_ping_monitored", ping_monitored)

        # Log the creation if auto_log is enabled
        if auto_log and user_id and username:
            monitoring_types = []
            if ssl_monitored:
                monitoring_types.append("SSL")
            if expiry_monitored:
                monitoring_types.append("expiry")
            if ping_monitored:
                monitoring_types.append("ping")

            monitoring_str = ", ".join(monitoring_types) if monitoring_types else "no"

            logger.info(f"Auto-logging domain creation: {name} (ID: {domain_id}) with {monitoring_str} monitoring")

            try:
                log_result = log_user_action(
                    user_id=user_id,
                    username=username,
                    action_type='create',
                    resource_type='domain',
                    resource_id=domain_id,
                    resource_name=name,
                    details=f'Added domain with {monitoring_str} monitoring',
                    ip_address=ip_address,
                    organization_id=organization_id
                )
                logger.info(f"Auto-log result: {log_result}")
            except Exception as e:
                logger.error(f"Error creating auto-log entry: {str(e)}", exc_info=True)

        return domain_id

def get_domain(domain_id):
    """Get domain by ID"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()
        if domain:
            # Get monitoring settings from organization settings
            org_id = domain.organization_id
            ssl_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ssl_monitored", False)
            expiry_monitored = get_organization_setting(org_id, f"domain_{domain.id}_expiry_monitored", False)
            ping_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ping_monitored", False)

            return {
                'id': domain.id,
                'name': domain.name,
                'organization_id': domain.organization_id,
                'created_at': domain.created_at.timestamp() if domain.created_at else None,
                'ssl_monitored': ssl_monitored,
                'expiry_monitored': expiry_monitored,
                'ping_monitored': ping_monitored
            }
        return None

# Removed redundant get_domain_by_id function - use get_domain instead

def get_domain_by_name(name):
    """Get domain by name"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.name == name).first()
        if domain:
            # Get monitoring settings from organization settings
            org_id = domain.organization_id
            ssl_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ssl_monitored", False)
            expiry_monitored = get_organization_setting(org_id, f"domain_{domain.id}_expiry_monitored", False)
            ping_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ping_monitored", False)

            return {
                'id': domain.id,
                'name': domain.name,
                'organization_id': domain.organization_id,
                'created_at': domain.created_at.timestamp() if domain.created_at else None,
                'ssl_monitored': ssl_monitored,
                'expiry_monitored': expiry_monitored,
                'ping_monitored': ping_monitored
            }
        return None

def get_domain_by_name_and_org(name, org_id):
    """Get domain by name and organization ID"""
    with get_db() as db:
        domain = db.query(Domain).filter(
            Domain.name == name,
            Domain.organization_id == org_id
        ).first()
        if domain:
            # Get monitoring settings from organization settings
            ssl_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ssl_monitored", False)
            expiry_monitored = get_organization_setting(org_id, f"domain_{domain.id}_expiry_monitored", False)
            ping_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ping_monitored", False)

            return {
                'id': domain.id,
                'name': domain.name,
                'organization_id': domain.organization_id,
                'created_at': domain.created_at.timestamp() if domain.created_at else None,
                'ssl_monitored': ssl_monitored,
                'expiry_monitored': expiry_monitored,
                'ping_monitored': ping_monitored
            }
        return None

def get_all_domains():
    """Get all domains"""
    with get_db() as db:
        domains = db.query(Domain).all()
        result = []

        for domain in domains:
            # Get monitoring settings from organization settings
            org_id = domain.organization_id
            ssl_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ssl_monitored", False)
            expiry_monitored = get_organization_setting(org_id, f"domain_{domain.id}_expiry_monitored", False)
            ping_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ping_monitored", False)

            result.append({
                'id': domain.id,
                'name': domain.name,
                'organization_id': domain.organization_id,
                'created_at': domain.created_at.timestamp() if domain.created_at else None,
                'ssl_monitored': ssl_monitored,
                'expiry_monitored': expiry_monitored,
                'ping_monitored': ping_monitored
            })

        return result

def get_domains_by_organization(org_id):
    """Get all domains for an organization"""
    with get_db() as db:
        domains = db.query(Domain).filter(Domain.organization_id == org_id).all()
        result = []

        for domain in domains:
            # Get monitoring settings from organization settings
            ssl_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ssl_monitored", False)
            expiry_monitored = get_organization_setting(org_id, f"domain_{domain.id}_expiry_monitored", False)
            ping_monitored = get_organization_setting(org_id, f"domain_{domain.id}_ping_monitored", False)

            result.append({
                'id': domain.id,
                'name': domain.name,
                'organization_id': domain.organization_id,
                'created_at': domain.created_at.timestamp() if domain.created_at else None,
                'ssl_monitored': ssl_monitored,
                'expiry_monitored': expiry_monitored,
                'ping_monitored': ping_monitored
            })

        return result

def update_domain(domain_id, name, ssl_monitored=False, expiry_monitored=False, ping_monitored=False):
    """Update domain details and monitoring options"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()
        if not domain:
            return False

        domain.name = name
        # Store monitoring options in the database
        # We'll use organization settings to store these values
        set_organization_setting(domain.organization_id, f"domain_{domain_id}_ssl_monitored", ssl_monitored)
        set_organization_setting(domain.organization_id, f"domain_{domain_id}_expiry_monitored", expiry_monitored)
        set_organization_setting(domain.organization_id, f"domain_{domain_id}_ping_monitored", ping_monitored)

        db.commit()
        return True

def delete_domain(domain_id):
    """Delete a domain"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.id == domain_id).first()
        if not domain:
            return False

        db.delete(domain)
        db.commit()
        return True

# Alert history functions
def add_alert_history(alert_id, domain_name, alert_type, status, message, action, user_id=None, username=None):
    """Add an entry to the alert history"""
    with get_db() as db:
        alert_history = AlertHistory(
            alert_id=alert_id,
            domain_name=domain_name,
            alert_type=alert_type,
            status=status,
            message=message,
            action=action,
            user_id=user_id,
            username=username
        )
        db.add(alert_history)
        db.commit()
        return True

# User action logging functions
def log_user_action(user_id, username, action_type, resource_type, resource_id=None, resource_name=None,
                   details=None, ip_address=None, organization_id=None):
    """
    Log a user action in the database

    Args:
        user_id (int): The ID of the user performing the action
        username (str): The username of the user performing the action
        action_type (str): The type of action (login, logout, create, update, delete, etc.)
        resource_type (str): The type of resource being acted upon (domain, organization, user, alert, etc.)
        resource_id (str, optional): The ID of the resource being acted upon
        resource_name (str, optional): The name of the resource being acted upon
        details (str, optional): Additional details about the action
        ip_address (str, optional): The IP address of the user
        organization_id (int, optional): The ID of the organization the action is related to

    Returns:
        bool: True if the action was logged successfully
    """
    import logging
    logger = logging.getLogger('certifly')
    from datetime import datetime

    try:
        logger.info(f"Logging user action: user={username}, action={action_type}, resource={resource_type}, resource_name={resource_name}")

        with get_db() as db:
            # Use local time (datetime.now()) instead of UTC time to match the timezone used in direct log creation
            log_entry = UserActionLog(
                user_id=user_id,
                username=username,
                action_type=action_type,
                resource_type=resource_type,
                resource_id=str(resource_id) if resource_id is not None else None,
                resource_name=resource_name,
                details=details,
                ip_address=ip_address,
                organization_id=organization_id,
                created_at=datetime.now()  # Use local time instead of default UTC
            )
            db.add(log_entry)
            db.commit()
            logger.info(f"Successfully logged user action with ID: {log_entry.id}")
            return True
    except Exception as e:
        logger.error(f"Error logging user action: {str(e)}", exc_info=True)
        return False

def get_user_action_logs(limit=50, offset=0, user_id=None, action_type=None,
                        resource_type=None, organization_id=None, start_date=None, end_date=None):
    """
    Get user action logs with filtering and pagination

    Args:
        limit (int): Maximum number of logs to return
        offset (int): Offset for pagination
        user_id (int, optional): Filter by user ID
        action_type (str, optional): Filter by action type
        resource_type (str, optional): Filter by resource type
        organization_id (int, optional): Filter by organization ID
        start_date (datetime, optional): Filter by start date (UTC)
        end_date (datetime, optional): Filter by end date (UTC)

    Returns:
        list: List of user action logs with UTC timestamps
    """
    import logging
    logger = logging.getLogger('certifly')

    logger.info(f"Getting logs with filters: user_id={user_id}, action_type={action_type}, "
                f"resource_type={resource_type}, organization_id={organization_id}, "
                f"start_date={start_date}, end_date={end_date}")

    try:
        with get_db() as db:
            query = db.query(UserActionLog)

            # Apply filters
            if user_id is not None:
                query = query.filter(UserActionLog.user_id == user_id)
            if action_type is not None:
                query = query.filter(UserActionLog.action_type == action_type)
            if resource_type is not None:
                query = query.filter(UserActionLog.resource_type == resource_type)
            if organization_id is not None:
                query = query.filter(UserActionLog.organization_id == organization_id)
            if start_date is not None:
                query = query.filter(UserActionLog.created_at >= start_date)
            if end_date is not None:
                query = query.filter(UserActionLog.created_at <= end_date)

            # Order by created_at descending (newest first)
            query = query.order_by(UserActionLog.created_at.desc())

            # Apply pagination
            logs = query.limit(limit).offset(offset).all()

            logger.info(f"Found {len(logs)} logs")

            # Get user profile images for all users in the logs
            user_ids = set(log.user_id for log in logs if log.user_id is not None)
            user_profile_images = {}

            if user_ids:
                users = db.query(User).filter(User.id.in_(user_ids)).all()
                for user in users:
                    user_profile_images[user.id] = user.profile_image

            # Convert to dictionaries with UTC timestamps
            # We'll handle timezone conversion in the template
            result = [
                {
                    'id': log.id,
                    'user_id': log.user_id,
                    'username': log.username,
                    'user_profile_image': user_profile_images.get(log.user_id) if log.user_id is not None else None,
                    'action_type': log.action_type,
                    'resource_type': log.resource_type,
                    'resource_id': log.resource_id,
                    'resource_name': log.resource_name,
                    'details': log.details,
                    'ip_address': log.ip_address,
                    'organization_id': log.organization_id,
                    'created_at': log.created_at.timestamp() if log.created_at else None,
                    # Add ISO format for easier debugging
                    'created_at_iso': log.created_at.isoformat() if log.created_at else None
                }
                for log in logs
            ]

            # Log the first few entries for debugging
            if result and len(result) > 0:
                logger.info(f"First log entry: id={result[0]['id']}, action={result[0]['action_type']}, "
                           f"resource={result[0]['resource_type']}, "
                           f"timestamp={result[0]['created_at']}, "
                           f"iso={result[0]['created_at_iso']}")

            return result
    except Exception as e:
        logger.error(f"Error getting logs: {str(e)}", exc_info=True)
        return []

def get_user_action_logs_count(user_id=None, action_type=None, resource_type=None,
                              organization_id=None, start_date=None, end_date=None):
    """
    Get count of user action logs with filtering

    Args:
        user_id (int, optional): Filter by user ID
        action_type (str, optional): Filter by action type
        resource_type (str, optional): Filter by resource type
        organization_id (int, optional): Filter by organization ID
        start_date (datetime, optional): Filter by start date
        end_date (datetime, optional): Filter by end date

    Returns:
        int: Count of user action logs
    """
    import logging
    logger = logging.getLogger('certifly')

    logger.info(f"Getting logs count with filters: user_id={user_id}, action_type={action_type}, "
                f"resource_type={resource_type}, organization_id={organization_id}, "
                f"start_date={start_date}, end_date={end_date}")

    try:
        with get_db() as db:
            query = db.query(UserActionLog)

            # Apply filters
            if user_id is not None:
                query = query.filter(UserActionLog.user_id == user_id)
            if action_type is not None:
                query = query.filter(UserActionLog.action_type == action_type)
            if resource_type is not None:
                query = query.filter(UserActionLog.resource_type == resource_type)
            if organization_id is not None:
                query = query.filter(UserActionLog.organization_id == organization_id)
            if start_date is not None:
                query = query.filter(UserActionLog.created_at >= start_date)
            if end_date is not None:
                query = query.filter(UserActionLog.created_at <= end_date)

            count = query.count()
            logger.info(f"Found {count} logs")
            return count
    except Exception as e:
        logger.error(f"Error getting logs count: {str(e)}", exc_info=True)
        return 0

def get_unique_action_types():
    """
    Get a list of unique action types from the logs

    Returns:
        list: List of unique action types
    """
    import logging
    logger = logging.getLogger('certifly')

    try:
        with get_db() as db:
            # Use distinct to get unique values
            action_types = db.query(UserActionLog.action_type).distinct().all()
            # Extract values from result tuples
            return [action_type[0] for action_type in action_types if action_type[0]]
    except Exception as e:
        logger.error(f"Error getting unique action types: {str(e)}", exc_info=True)
        return []

def get_unique_resource_types():
    """
    Get a list of unique resource types from the logs

    Returns:
        list: List of unique resource types
    """
    import logging
    logger = logging.getLogger('certifly')

    try:
        with get_db() as db:
            # Use distinct to get unique values
            resource_types = db.query(UserActionLog.resource_type).distinct().all()
            # Extract values from result tuples
            return [resource_type[0] for resource_type in resource_types if resource_type[0]]
    except Exception as e:
        logger.error(f"Error getting unique resource types: {str(e)}", exc_info=True)
        return []

def get_alert_history(limit=50, offset=0):
    """Get alert history with pagination"""
    with get_db() as db:
        alerts = db.query(AlertHistory).order_by(AlertHistory.created_at.desc()).limit(limit).offset(offset).all()
        return [
            {
                'id': alert.id,
                'alert_id': alert.alert_id,
                'domain_name': alert.domain_name,
                'alert_type': alert.alert_type,
                'status': alert.status,
                'message': alert.message,
                'action': alert.action,
                'user_id': alert.user_id,
                'username': alert.username,
                'created_at': alert.created_at.timestamp() if alert.created_at else None
            }
            for alert in alerts
        ]

def get_alert_history_count():
    """Get total count of alert history entries"""
    with get_db() as db:
        return db.query(AlertHistory).count()

def get_alerts_by_type(alert_type, days=30):
    """Get alerts by type for the last X days"""
    with get_db() as db:
        # Calculate the start time (X days ago)
        start_time = datetime.utcnow() - timedelta(days=days)

        # Get all alerts of the specified type in the time period
        alerts = db.query(AlertHistory).filter(
            AlertHistory.alert_type == alert_type,
            AlertHistory.created_at >= start_time
        ).order_by(AlertHistory.created_at.desc()).all()

        return [
            {
                'id': alert.id,
                'alert_id': alert.alert_id,
                'domain': alert.domain_name,
                'alert_type': alert.alert_type,
                'status': alert.status,
                'message': alert.message,
                'action': alert.action,
                'user_id': alert.user_id,
                'username': alert.username,
                'created_at': alert.created_at,
                'acknowledged': alert.action == 'acknowledged'
            }
            for alert in alerts
        ]

def get_alerts(days=30):
    """Get all alerts for the last X days"""
    with get_db() as db:
        # Calculate the start time (X days ago)
        start_time = datetime.utcnow() - timedelta(days=days)

        # Get all alerts in the time period
        alerts = db.query(AlertHistory).filter(
            AlertHistory.created_at >= start_time
        ).order_by(AlertHistory.created_at.desc()).all()

        return [
            {
                'id': alert.id,
                'alert_id': alert.alert_id,
                'domain': alert.domain_name,
                'alert_type': alert.alert_type,
                'status': alert.status,
                'message': alert.message,
                'action': alert.action,
                'user_id': alert.user_id,
                'username': alert.username,
                'created_at': alert.created_at,
                'acknowledged': alert.action == 'acknowledged'
            }
            for alert in alerts
        ]

# User preference functions
def get_user_preference(user_id, key, default=None):
    """Get a user preference from the database"""
    with get_db() as db:
        preference = db.query(UserPreference).filter(
            UserPreference.user_id == user_id,
            UserPreference.key == key
        ).first()

        if preference and preference.value:
            # Handle boolean values stored as strings
            if preference.value == 'True':
                return True
            elif preference.value == 'False':
                return False
            return preference.value
        return default

def set_user_preference(user_id, key, value):
    """Set a user preference in the database"""
    # Convert boolean to string
    if isinstance(value, bool):
        value = str(value)

    with get_db() as db:
        preference = db.query(UserPreference).filter(
            UserPreference.user_id == user_id,
            UserPreference.key == key
        ).first()

        if preference:
            preference.value = value
        else:
            preference = UserPreference(
                user_id=user_id,
                key=key,
                value=value
            )
            db.add(preference)

        db.commit()
        return True

# Settings functions
def get_setting(key, default=None):
    """Get a setting from the database"""
    with get_db() as db:
        setting = db.query(Setting).filter(Setting.key == key).first()
        if setting and setting.value:
            try:
                return json.loads(setting.value)
            except json.JSONDecodeError:
                return setting.value
        return default

def set_setting(key, value):
    """Set a setting in the database"""
    with get_db() as db:
        setting = db.query(Setting).filter(Setting.key == key).first()

        # Convert value to JSON string if it's not already a string
        if not isinstance(value, str):
            value = json.dumps(value)

        if setting:
            setting.value = value
        else:
            setting = Setting(key=key, value=value)
            db.add(setting)

        db.commit()
        return True

# Organization Settings functions
def get_organization_setting(org_id, key, default=None):
    """Get a setting for a specific organization"""
    with get_db() as db:
        setting = db.query(OrganizationSetting).filter(
            OrganizationSetting.organization_id == org_id,
            OrganizationSetting.key == key
        ).first()

        if setting and setting.value:
            try:
                return json.loads(setting.value)
            except json.JSONDecodeError:
                return setting.value
        return default

def set_organization_setting(org_id, key, value):
    """Set a setting for a specific organization"""
    with get_db() as db:
        setting = db.query(OrganizationSetting).filter(
            OrganizationSetting.organization_id == org_id,
            OrganizationSetting.key == key
        ).first()

        # Convert value to JSON string if it's not already a string
        if not isinstance(value, str):
            value = json.dumps(value)

        if setting:
            setting.value = value
        else:
            setting = OrganizationSetting(
                organization_id=org_id,
                key=key,
                value=value
            )
            db.add(setting)

        db.commit()
        return True

# Cache functions
def get_cache(key):
    """Get a value from the cache"""
    with get_db() as db:
        cache = db.query(Cache).filter(
            Cache.key == key,
            (Cache.expires_at > datetime.utcnow()) | (Cache.expires_at.is_(None))
        ).first()

        if cache and cache.value:
            try:
                return json.loads(cache.value)
            except json.JSONDecodeError:
                return cache.value
        return None

def set_cache(key, value, expires_in=86400):  # Default: 1 day
    """Set a value in the cache"""
    with get_db() as db:
        cache = db.query(Cache).filter(Cache.key == key).first()

        # Convert value to JSON string if it's not already a string
        if not isinstance(value, str):
            value = json.dumps(value)

        expires_at = datetime.utcnow() + timedelta(seconds=expires_in) if expires_in else None

        if cache:
            cache.value = value
            cache.expires_at = expires_at
        else:
            cache = Cache(key=key, value=value, expires_at=expires_at)
            db.add(cache)

        db.commit()
        return True

def clear_cache(key):
    """Clear a specific cache entry"""
    with get_db() as db:
        db.query(Cache).filter(Cache.key == key).delete()
        db.commit()
        return True

def clear_cache_by_prefix(prefix):
    """Clear all cache entries with a specific prefix"""
    with get_db() as db:
        db.query(Cache).filter(Cache.key.like(f"{prefix}%")).delete()
        db.commit()
        return True

def clear_expired_cache():
    """Clear all expired cache entries"""
    with get_db() as db:
        db.query(Cache).filter(Cache.expires_at <= datetime.utcnow()).delete()
        db.commit()
        return True

# Monitoring functions
def record_ssl_check(domain_name, status, expiry_date, issuer, subject):
    """Record an SSL certificate check"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain:
            return False

        ssl_check = SSLCheck(
            domain_id=domain.id,
            status=status,
            expiry_date=expiry_date,
            issuer=issuer,
            subject=subject
        )
        db.add(ssl_check)
        db.commit()
        return True

def calculate_uptime_percentage(domain_name, days=7, hours=None):
    """Calculate uptime percentage for a domain over the last X days or hours"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain:
            return None

        # Calculate the start time based on days or hours
        if hours is not None:
            # If hours is provided, use it instead of days
            start_time = datetime.utcnow() - timedelta(hours=hours)
        else:
            # Otherwise use days
            start_time = datetime.utcnow() - timedelta(days=days)

        # Get all ping checks for this domain in the time period
        ping_checks = db.query(PingCheck).filter(
            PingCheck.domain_id == domain.id,
            PingCheck.checked_at >= start_time
        ).all()

        if not ping_checks:
            return None

        # Count up vs down checks
        up_count = sum(1 for check in ping_checks if check.status == 'up')
        total_count = len(ping_checks)

        # Calculate percentage
        if total_count > 0:
            return (up_count / total_count) * 100
        return None

def get_ping_history(domain_name, hours=12):
    """Get ping history for a domain over the last X hours"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain:
            return []

        # Calculate the start time (X hours ago)
        start_time = datetime.utcnow() - timedelta(hours=hours)

        # Get all ping checks for this domain in the time period
        ping_checks = db.query(PingCheck).filter(
            PingCheck.domain_id == domain.id,
            PingCheck.checked_at >= start_time
        ).order_by(PingCheck.checked_at.asc()).all()

        return [
            {
                'status': check.status,
                'response_time': check.response_time,
                'checked_at': check.checked_at.timestamp() if check.checked_at else None
            }
            for check in ping_checks
        ]

def get_ping_response_history(domain_name, hours=24):
    """Get ping response time history for a domain over the last X hours"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain:
            return []

        # Calculate the start time (X hours ago)
        start_time = datetime.utcnow() - timedelta(hours=hours)

        # Get all ping checks for this domain in the time period where status is 'up'
        ping_checks = db.query(PingCheck).filter(
            PingCheck.domain_id == domain.id,
            PingCheck.checked_at >= start_time,
            PingCheck.status == 'up'  # Only include successful pings
        ).order_by(PingCheck.checked_at.asc()).all()

        # Format the data for the chart
        # Note: We're explicitly marking the timestamp as UTC by adding 'Z' to the ISO format
        return [
            {
                'timestamp': int(check.checked_at.timestamp() * 1000) if check.checked_at else None,  # Convert to milliseconds for JavaScript
                'response_time': check.response_time,
                'formatted_time': check.checked_at.strftime('%Y-%m-%d %H:%M:%S') if check.checked_at else None,
                'iso_time': check.checked_at.isoformat() + 'Z' if check.checked_at else None  # Add 'Z' to indicate UTC
            }
            for check in ping_checks
        ]

def record_domain_expiry_check(domain_name, status, expiry_date, registrar):
    """Record a domain expiry check"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain:
            return False

        domain_check = DomainExpiryCheck(
            domain_id=domain.id,
            status=status,
            expiry_date=expiry_date,
            registrar=registrar
        )
        db.add(domain_check)
        db.commit()
        return True

def record_ping_status(domain_name, status, response_time):
    """Record a ping check"""
    with get_db() as db:
        domain = db.query(Domain).filter(Domain.name == domain_name).first()
        if not domain:
            return False

        ping_check = PingCheck(
            domain_id=domain.id,
            status=status,
            response_time=response_time
        )
        db.add(ping_check)
        db.commit()
        return True

# Initialize database
def init_db():
    """Initialize the database by creating all tables"""
    Base.metadata.create_all(bind=engine)

def check_connection():
    """Check if database connection is working"""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT 1")
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Database connection check failed: {str(e)}")
        return False
