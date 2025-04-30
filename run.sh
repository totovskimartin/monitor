#!/bin/bash
set -e

# Initialize the database if it doesn't exist
python -c "from database import init_db; init_db()"

# Start the Flask application
exec python -m flask run --host=0.0.0.0
