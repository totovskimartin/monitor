# Certifly - SSL Certificate and Domain Monitoring

A modern web application for monitoring SSL certificates, domain expiration, and website uptime. Certifly helps you keep track of your domains and certificates to prevent unexpected downtime.

## Features

- **SSL Certificate Monitoring**: Track certificate expiration dates and receive alerts before they expire
- **Domain Expiry Tracking**: Monitor domain registration expiration dates
- **Website Uptime Monitoring**: Check if your websites are up and running
- **Multi-Organization Support**: Manage domains across different organizations
- **User Management**: Role-based access control with admin and regular users
- **Customizable Alerts**: Configure alerts for different thresholds
- **Multiple Notification Channels**: Email, Slack, MS Teams, Discord, Telegram, and more
- **Exportable Reports**: Generate and export reports in CSV, PDF, and Excel formats
- **Modern UI**: Clean, responsive interface with dark/light theme support
- **Containerized Deployment**: Easy deployment with Docker and Docker Compose

## Requirements

- Docker
- Docker Compose

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/totovskimartin/certifly.git
   cd certifly
   ```

2. Start the application:
   ```bash
   docker-compose up -d
   ```

3. Access the application at http://localhost:5000

4. Log in with the default admin account:
   - Username: `admin`
   - Password: `admin`

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

See `.env.example` for a list of all environment variables. The main ones are:

- `FLASK_ENV`: Set to `production` for production deployment
- `CERT_MONITOR_DATA_DIR`: Directory to store application data
- `SECRET_KEY`: Secret key for session management
- `DB_*`: Database connection settings
- `WHOIS_API_KEY`: API key for domain expiry lookups

## Configuration

### Database

The application uses PostgreSQL by default. You can configure the database connection using the environment variables in `.env`.

### WHOIS API Key

To enable domain expiry monitoring, you need to obtain a WHOIS API key from a provider like [whoisxmlapi.com](https://www.whoisxmlapi.com/) or similar services. Set this key in the `.env` file or through the application settings interface.

## Recent Updates

- Fixed export functionality to properly generate PDF and Excel files in addition to CSV
- Improved UI with consistent theme support
- Added multi-organization support
- Enhanced notification system with multiple channels

## License

[MIT License](LICENSE)
