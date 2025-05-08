#!/usr/bin/env python3
"""
Migration script to add uptime_statistics table
"""

import os
import sys
import logging
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('migration')

# Database connection parameters
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5432')
DB_NAME = os.getenv('DB_NAME', 'certifly')
DB_USER = os.getenv('DB_USER', 'certifly')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'password')

def get_connection():
    """Get a connection to the database"""
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        return conn
    except psycopg2.Error as e:
        logger.error(f"Error connecting to the database: {e}")
        sys.exit(1)

def check_table_exists(conn, table):
    """Check if a table exists in the database"""
    with conn.cursor() as cursor:
        cursor.execute(
            sql.SQL("""
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.tables
                    WHERE table_name = %s
                )
            """),
            (table,)
        )
        return cursor.fetchone()[0]

def create_uptime_statistics_table(conn):
    """Create the uptime_statistics table"""
    with conn.cursor() as cursor:
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS uptime_statistics (
                    id SERIAL PRIMARY KEY,
                    domain_id INTEGER REFERENCES domains(id),
                    period_type VARCHAR(20),
                    period_start TIMESTAMP,
                    period_end TIMESTAMP,
                    uptime_percentage INTEGER,
                    downtime_duration INTEGER,
                    checks_total INTEGER,
                    checks_up INTEGER,
                    checks_down INTEGER,
                    checks_unknown INTEGER,
                    avg_response_time INTEGER,
                    min_response_time INTEGER,
                    max_response_time INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(domain_id, period_type, period_start)
                )
            """)
            logger.info("Created uptime_statistics table")
            return True
        except psycopg2.Error as e:
            logger.error(f"Error creating uptime_statistics table: {e}")
            return False

def main():
    """Main migration function"""
    logger.info("Starting migration to add uptime_statistics table")

    conn = get_connection()

    # Check if the table already exists
    if check_table_exists(conn, 'uptime_statistics'):
        logger.info("Table uptime_statistics already exists")
        conn.close()
        return

    # Create the uptime_statistics table
    success = create_uptime_statistics_table(conn)

    if success:
        logger.info("Migration completed successfully")
    else:
        logger.error("Migration failed")

    conn.close()

if __name__ == "__main__":
    main()
