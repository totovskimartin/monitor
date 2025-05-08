#!/bin/bash
set -e

# Wait for database to be ready
./init-db.sh

# Start the Flask application
if [ "$FLASK_ENV" = "production" ]; then
  echo "Starting application in production mode with Gunicorn"
  exec gunicorn --bind 0.0.0.0:5000 --workers 4 --threads 2 --timeout 60 "app:app"
else
  echo "Starting application in development mode"
  exec python -m flask run --host=0.0.0.0
fi
