#!/usr/bin/env python3
import os
import sys
import json
from datetime import datetime, timedelta
import logging
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('check_logs')

# Database configuration
DB_USER = os.getenv('DB_USER', 'certifly')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'certifly')

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

def get_engine():
    """Get SQLAlchemy engine"""
    return create_engine(DATABASE_URL)

def get_session():
    """Get SQLAlchemy session"""
    engine = get_engine()
    Session = sessionmaker(bind=engine)
    return Session()

def check_logs():
    """Check logs in the database"""
    try:
        session = get_session()

        # Check if the user_action_logs table exists
        check_table_query = text("SELECT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'user_action_logs')")
        table_exists = session.execute(check_table_query).scalar()
        print(f"user_action_logs table exists: {table_exists}")

        if not table_exists:
            print("ERROR: user_action_logs table does not exist!")
            return False

        # Check table structure
        columns_query = text("SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'user_action_logs'")
        columns = session.execute(columns_query).fetchall()
        print("\nTable structure:")
        for column in columns:
            print(f"  {column.column_name}: {column.data_type}")

        # Get all logs
        query = text("SELECT * FROM user_action_logs ORDER BY created_at DESC LIMIT 50")
        result = session.execute(query)

        logs = []
        for row in result:
            log = {
                'id': row.id,
                'user_id': row.user_id,
                'username': row.username,
                'action_type': row.action_type,
                'resource_type': row.resource_type,
                'resource_id': row.resource_id,
                'resource_name': row.resource_name,
                'details': row.details,
                'ip_address': row.ip_address,
                'organization_id': row.organization_id,
                'created_at': row.created_at.isoformat() if row.created_at else None
            }
            logs.append(log)

        print(f"Found {len(logs)} logs")

        # Print logs
        for log in logs:
            print(f"ID: {log['id']}, Time: {log['created_at']}, User: {log['username']}, Action: {log['action_type']}, Resource: {log['resource_type']}, Resource Name: {log['resource_name']}, Details: {log['details']}")

        # Check for specific action types
        create_logs = [log for log in logs if log['action_type'] == 'create']
        update_logs = [log for log in logs if log['action_type'] == 'update']
        delete_logs = [log for log in logs if log['action_type'] == 'delete']

        print(f"\nFound {len(create_logs)} create logs")
        print(f"Found {len(update_logs)} update logs")
        print(f"Found {len(delete_logs)} delete logs")

        # Check for domain logs
        domain_logs = [log for log in logs if log['resource_type'] == 'domain']
        print(f"\nFound {len(domain_logs)} domain logs")

        # Check for domain create logs
        domain_create_logs = [log for log in logs if log['resource_type'] == 'domain' and log['action_type'] == 'create']
        print(f"Found {len(domain_create_logs)} domain create logs")

        # Print domain create logs
        if domain_create_logs:
            print("\nDomain create logs:")
            for log in domain_create_logs:
                print(f"ID: {log['id']}, Time: {log['created_at']}, User: {log['username']}, Resource Name: {log['resource_name']}, Details: {log['details']}")

    except Exception as e:
        logger.error(f"Error checking logs: {e}")
        return False

    return True

def test_log_creation():
    """Test creating a log entry directly"""
    try:
        session = get_session()

        # Create a test log entry
        now = datetime.now()
        query = text("""
            INSERT INTO user_action_logs
            (user_id, username, action_type, resource_type, resource_name, details, created_at)
            VALUES (:user_id, :username, :action_type, :resource_type, :resource_name, :details, :created_at)
            RETURNING id
        """)

        params = {
            'user_id': 1,
            'username': 'test_user',
            'action_type': 'create',
            'resource_type': 'domain',
            'resource_name': 'test-domain.com',
            'details': 'Test log entry',
            'created_at': now
        }

        try:
            result = session.execute(query, params)
            log_id = result.scalar()
            session.commit()
            print(f"\nSuccessfully created test log entry with ID: {log_id}")
            return True
        except Exception as e:
            session.rollback()
            print(f"\nError creating test log entry: {e}")
            return False

    except Exception as e:
        logger.error(f"Error in test_log_creation: {e}")
        return False

def test_log_user_action():
    """Test the log_user_action function from database.py"""
    try:
        # Import the database module
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        import database as db

        # Call the log_user_action function
        result = db.log_user_action(
            user_id=1,
            username='test_user',
            action_type='create',
            resource_type='domain',
            resource_id=999,
            resource_name='test-domain-from-function.com',
            details='Test log entry from log_user_action function',
            ip_address='127.0.0.1',
            organization_id=1
        )

        print(f"\nResult from log_user_action function: {result}")

        # Check if the log entry was created
        check_logs()

        return result
    except Exception as e:
        logger.error(f"Error in test_log_user_action: {e}")
        return False

if __name__ == "__main__":
    check_logs()

    print("\nOptions:")
    print("1. Test creating a log entry directly")
    print("2. Test the log_user_action function")
    print("3. Exit")

    choice = input("\nEnter your choice (1-3): ")

    if choice == '1':
        test_log_creation()
    elif choice == '2':
        test_log_user_action()
    else:
        print("Exiting...")
