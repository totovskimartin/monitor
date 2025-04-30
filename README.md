# Certificates Web Application

A web application for monitoring SSL certificates and domain health.

## Requirements

- Docker
- Docker Compose

## Quick Start

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd certificates-web
   ```

2. Start the application:
   ```bash
   docker-compose up -d
   ```

3. Access the application at http://localhost:5000

## Development

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   ```bash
   cp .env.example .env
   ```

4. Run the application:
   ```bash
   python -m flask run
   ```

## Environment Variables

- `FLASK_ENV`: Set to `production` or `development`
- `CERT_MONITOR_DATA_DIR`: Directory for storing application data
