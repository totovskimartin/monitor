#!/usr/bin/env python3
"""
Migration script to add profile_image column to users table
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

def check_column_exists(conn, table, column):
    """Check if a column exists in a table"""
    with conn.cursor() as cursor:
        cursor.execute(
            sql.SQL("""
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.columns
                    WHERE table_name = %s AND column_name = %s
                )
            """),
            (table, column)
        )
        return cursor.fetchone()[0]

def add_column(conn, table, column, data_type):
    """Add a column to a table"""
    with conn.cursor() as cursor:
        try:
            cursor.execute(
                sql.SQL("ALTER TABLE {} ADD COLUMN IF NOT EXISTS {} {}").format(
                    sql.Identifier(table),
                    sql.Identifier(column),
                    sql.SQL(data_type)
                )
            )
            logger.info(f"Added column {column} to table {table}")
            return True
        except psycopg2.Error as e:
            logger.error(f"Error adding column: {e}")
            return False

def main():
    """Main migration function"""
    logger.info("Starting migration to add profile_image column to users table")

    conn = get_connection()

    # Check if the column already exists
    if check_column_exists(conn, 'users', 'profile_image'):
        logger.info("Column profile_image already exists in users table")
        conn.close()
        return

    # Add the profile_image column
    success = add_column(conn, 'users', 'profile_image', 'TEXT')

    if success:
        logger.info("Migration completed successfully")
    else:
        logger.error("Migration failed")

    conn.close()

if __name__ == "__main__":
    main()
